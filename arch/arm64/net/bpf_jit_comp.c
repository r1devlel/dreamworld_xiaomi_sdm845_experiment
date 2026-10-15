/*
 * BPF JIT compiler for ARM64
 *
 * Copyright (C) 2014-2016 Zi Shen Lim <zlim.lnx@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define pr_fmt(fmt) "bpf_jit: " fmt

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/kallsyms.h>
#include <linux/memory.h>
#include <linux/printk.h>
#include <linux/sizes.h>
#include <linux/skbuff.h>
#include <linux/slab.h>

#include <asm/byteorder.h>
#include <asm/cacheflush.h>
#include <asm/debug-monitors.h>

#include "bpf_jit.h"

#define TMP_REG_1 (MAX_BPF_JIT_REG + 0)
#define TMP_REG_2 (MAX_BPF_JIT_REG + 1)
#define TCALL_CNT (MAX_BPF_JIT_REG + 2)
#define TMP_REG_3 (MAX_BPF_JIT_REG + 3)

/* Map BPF registers to A64 registers */
static const int bpf2a64[] = {
	/* return value from in-kernel function, and exit value from eBPF */
	[BPF_REG_0] = A64_R(7),
	/* arguments from eBPF program to in-kernel function */
	[BPF_REG_1] = A64_R(0),
	[BPF_REG_2] = A64_R(1),
	[BPF_REG_3] = A64_R(2),
	[BPF_REG_4] = A64_R(3),
	[BPF_REG_5] = A64_R(4),
	/* callee saved registers that in-kernel function will preserve */
	[BPF_REG_6] = A64_R(19),
	[BPF_REG_7] = A64_R(20),
	[BPF_REG_8] = A64_R(21),
	[BPF_REG_9] = A64_R(22),
	/* read-only frame pointer to access stack */
	[BPF_REG_FP] = A64_R(25),
	/* temporary registers for internal BPF JIT */
	[TMP_REG_1] = A64_R(10),
	[TMP_REG_2] = A64_R(11),
	[TMP_REG_3] = A64_R(12),
	/* tail_call_cnt */
	[TCALL_CNT] = A64_R(26),
	/* temporary register for blinding constants */
	[BPF_REG_AX] = A64_R(9),
};

struct jit_ctx {
	const struct bpf_prog *prog;
	int idx;
	int epilogue_offset;
	int *offset;
	__le32 *image;
	u32 stack_size;
};

struct bpf_plt {
	u32 insn_ldr;
	u32 insn_br;
	u64 target;
};

#define PLT_TARGET_SIZE	 sizeof(u64)
#define PLT_TARGET_OFFSET offsetof(struct bpf_plt, target)

static inline void emit(const u32 insn, struct jit_ctx *ctx)
{
	if (ctx->image != NULL)
		ctx->image[ctx->idx] = cpu_to_le32(insn);

	ctx->idx++;
}

static inline void emit_a64_mov_i(const int is64, const int reg,
				  const s32 val, struct jit_ctx *ctx)
{
	u16 hi = val >> 16;
	u16 lo = val & 0xffff;

	if (hi & 0x8000) {
		if (hi == 0xffff) {
			emit(A64_MOVN(is64, reg, (u16)~lo, 0), ctx);
		} else {
			emit(A64_MOVN(is64, reg, (u16)~hi, 16), ctx);
			if (lo != 0xffff)
				emit(A64_MOVK(is64, reg, lo, 0), ctx);
		}
	} else {
		emit(A64_MOVZ(is64, reg, lo, 0), ctx);
		if (hi)
			emit(A64_MOVK(is64, reg, hi, 16), ctx);
	}
}

static int i64_i16_blocks(const u64 val, bool inverse)
{
	return (((val >>  0) & 0xffff) != (inverse ? 0xffff : 0x0000)) +
	       (((val >> 16) & 0xffff) != (inverse ? 0xffff : 0x0000)) +
	       (((val >> 32) & 0xffff) != (inverse ? 0xffff : 0x0000)) +
	       (((val >> 48) & 0xffff) != (inverse ? 0xffff : 0x0000));
}

static inline void emit_a64_mov_i64(const int reg, const u64 val,
				    struct jit_ctx *ctx)
{
	u64 nrm_tmp = val, rev_tmp = ~val;
	bool inverse;
	int shift;

	if (!(nrm_tmp >> 32))
		return emit_a64_mov_i(0, reg, (u32)val, ctx);

	inverse = i64_i16_blocks(nrm_tmp, true) < i64_i16_blocks(nrm_tmp, false);
	shift = max(round_down((inverse ? (fls64(rev_tmp) - 1) :
					  (fls64(nrm_tmp) - 1)), 16), 0);
	if (inverse)
		emit(A64_MOVN(1, reg, (rev_tmp >> shift) & 0xffff, shift), ctx);
	else
		emit(A64_MOVZ(1, reg, (nrm_tmp >> shift) & 0xffff, shift), ctx);
	shift -= 16;
	while (shift >= 0) {
		if (((nrm_tmp >> shift) & 0xffff) != (inverse ? 0xffff : 0x0000))
			emit(A64_MOVK(1, reg, (nrm_tmp >> shift) & 0xffff, shift), ctx);
		shift -= 16;
	}
}

/*
 * Kernel addresses in the vmalloc space use at most 48 bits, and the
 * remaining bits are guaranteed to be 0x1. So we can compose the address
 * with a fixed length movn/movk/movk sequence.
 */
static inline void emit_addr_mov_i64(const int reg, const u64 val,
				     struct jit_ctx *ctx)
{
	u64 tmp = val;
	int shift = 0;

	emit(A64_MOVN(1, reg, ~tmp & 0xffff, shift), ctx);
	while (shift < 32) {
		tmp >>= 16;
		shift += 16;
		emit(A64_MOVK(1, reg, tmp & 0xffff, shift), ctx);
	}
}

static inline int bpf2a64_offset(int bpf_to, int bpf_from,
				 const struct jit_ctx *ctx)
{
	int to = ctx->offset[bpf_to];
	/* -1 to account for the Branch instruction */
	int from = ctx->offset[bpf_from] - 1;

	return to - from;
}

static void jit_fill_hole(void *area, unsigned int size)
{
	__le32 *ptr;
	/* We are guaranteed to have aligned memory. */
	for (ptr = area; size >= sizeof(u32); size -= sizeof(u32))
		*ptr++ = cpu_to_le32(AARCH64_BREAK_FAULT);
}

static inline int epilogue_offset(const struct jit_ctx *ctx)
{
	int to = ctx->epilogue_offset;
	int from = ctx->idx;

	return to - from;
}

/* Stack must be multiples of 16B */
#define STACK_ALIGN(sz) (((sz) + 15) & ~15)

/* Offset of the NOP instruction that can be patched to a trampoline call. */
#define POKE_OFFSET 1
#define BPF_TRAMPOLINE_NATIVE_PATCH_INSNS 4

/* Tail call offset to jump into, after the trampoline patch site. */
#define PROLOGUE_OFFSET 9

static int build_prologue(struct jit_ctx *ctx)
{
	const struct bpf_prog *prog = ctx->prog;
	const u8 r6 = bpf2a64[BPF_REG_6];
	const u8 r7 = bpf2a64[BPF_REG_7];
	const u8 r8 = bpf2a64[BPF_REG_8];
	const u8 r9 = bpf2a64[BPF_REG_9];
	const u8 fp = bpf2a64[BPF_REG_FP];
	const u8 tcc = bpf2a64[TCALL_CNT];
	const int idx0 = ctx->idx;
	int cur_offset;

	/*
	 * BPF prog stack layout
	 *
	 *                         high
	 * original A64_SP =>   0:+-----+ BPF prologue
	 *                        |FP/LR|
	 * current A64_FP =>  -16:+-----+
	 *                        | ... | callee saved registers
	 * BPF fp register => -64:+-----+ <= (BPF_FP)
	 *                        |     |
	 *                        | ... | BPF prog stack
	 *                        |     |
	 *                        +-----+ <= (BPF_FP - prog->aux->stack_depth)
	 *                        |RSVD | JIT scratchpad
	 * current A64_SP =>      +-----+ <= (BPF_FP - ctx->stack_size)
	 *                        |     |
	 *                        | ... | Function call stack
	 *                        |     |
	 *                        +-----+
	 *                          low
	 *
	 */

	/* Preserve the caller return address across an optional trampoline call. */
	emit(A64_MOV(1, A64_R(9), A64_LR), ctx);
	emit(A64_NOP, ctx);

	/* Save FP and LR registers to stay align with ARM64 AAPCS */
	emit(A64_PUSH(A64_FP, A64_LR, A64_SP), ctx);
	emit(A64_MOV(1, A64_FP, A64_SP), ctx);

	/* Save callee-saved registers */
	emit(A64_PUSH(r6, r7, A64_SP), ctx);
	emit(A64_PUSH(r8, r9, A64_SP), ctx);
	emit(A64_PUSH(fp, tcc, A64_SP), ctx);

	/* Set up BPF prog stack base register */
	emit(A64_MOV(1, fp, A64_SP), ctx);

	/* Initialize tail_call_cnt */
	emit(A64_MOVZ(1, tcc, 0, 0), ctx);

	cur_offset = ctx->idx - idx0;
	if (cur_offset != PROLOGUE_OFFSET) {
		pr_err_once("PROLOGUE_OFFSET = %d, expected %d!\n",
			    cur_offset, PROLOGUE_OFFSET);
		return -1;
	}

	/* 4 byte extra for skb_copy_bits buffer */
	ctx->stack_size = prog->aux->stack_depth + 4;
	ctx->stack_size = STACK_ALIGN(ctx->stack_size);

	/* Set up function call stack */
	emit(A64_SUB_I(1, A64_SP, A64_SP, ctx->stack_size), ctx);
	return 0;
}

static int out_offset = -1; /* initialized on the first pass of build_body() */
static int emit_bpf_tail_call(struct jit_ctx *ctx)
{
	/* bpf_tail_call(void *prog_ctx, struct bpf_array *array, u64 index) */
	const u8 r2 = bpf2a64[BPF_REG_2];
	const u8 r3 = bpf2a64[BPF_REG_3];

	const u8 tmp = bpf2a64[TMP_REG_1];
	const u8 prg = bpf2a64[TMP_REG_2];
	const u8 tcc = bpf2a64[TCALL_CNT];
	const int idx0 = ctx->idx;
#define cur_offset (ctx->idx - idx0)
#define jmp_offset (out_offset - (cur_offset))
	size_t off;

	/* if (index >= array->map.max_entries)
	 *     goto out;
	 */
	off = offsetof(struct bpf_array, map.max_entries);
	emit_a64_mov_i64(tmp, off, ctx);
	emit(A64_LDR32(tmp, r2, tmp), ctx);
	emit(A64_MOV(0, r3, r3), ctx);
	emit(A64_CMP(0, r3, tmp), ctx);
	emit(A64_B_(A64_COND_CS, jmp_offset), ctx);

	/* if (tail_call_cnt > MAX_TAIL_CALL_CNT)
	 *     goto out;
	 * tail_call_cnt++;
	 */
	emit_a64_mov_i64(tmp, MAX_TAIL_CALL_CNT, ctx);
	emit(A64_CMP(1, tcc, tmp), ctx);
	emit(A64_B_(A64_COND_HI, jmp_offset), ctx);
	emit(A64_ADD_I(1, tcc, tcc, 1), ctx);

	/* prog = array->ptrs[index];
	 * if (prog == NULL)
	 *     goto out;
	 */
	off = offsetof(struct bpf_array, ptrs);
	emit_a64_mov_i64(tmp, off, ctx);
	emit(A64_ADD(1, tmp, r2, tmp), ctx);
	emit(A64_LSL(1, prg, r3, 3), ctx);
	emit(A64_LDR64(prg, tmp, prg), ctx);
	emit(A64_CBZ(1, prg, jmp_offset), ctx);

	/* goto *(prog->bpf_func + prologue_offset); */
	off = offsetof(struct bpf_prog, bpf_func);
	emit_a64_mov_i64(tmp, off, ctx);
	emit(A64_LDR64(tmp, prg, tmp), ctx);
	emit(A64_ADD_I(1, tmp, tmp, sizeof(u32) * PROLOGUE_OFFSET), ctx);
	emit(A64_ADD_I(1, A64_SP, A64_SP, ctx->stack_size), ctx);
	emit(A64_BR(tmp), ctx);

	/* out: */
	if (out_offset == -1)
		out_offset = cur_offset;
	if (cur_offset != out_offset) {
		pr_err_once("tail_call out_offset = %d, expected %d!\n",
			    cur_offset, out_offset);
		return -1;
	}
	return 0;
#undef cur_offset
#undef jmp_offset
}

static void build_epilogue(struct jit_ctx *ctx)
{
	const u8 r0 = bpf2a64[BPF_REG_0];
	const u8 r6 = bpf2a64[BPF_REG_6];
	const u8 r7 = bpf2a64[BPF_REG_7];
	const u8 r8 = bpf2a64[BPF_REG_8];
	const u8 r9 = bpf2a64[BPF_REG_9];
	const u8 fp = bpf2a64[BPF_REG_FP];

	/* We're done with BPF stack */
	emit(A64_ADD_I(1, A64_SP, A64_SP, ctx->stack_size), ctx);

	/* Restore fs (x25) and x26 */
	emit(A64_POP(fp, A64_R(26), A64_SP), ctx);

	/* Restore callee-saved register */
	emit(A64_POP(r8, r9, A64_SP), ctx);
	emit(A64_POP(r6, r7, A64_SP), ctx);

	/* Restore FP/LR registers */
	emit(A64_POP(A64_FP, A64_LR, A64_SP), ctx);

	/* Set return value */
	emit(A64_MOV(1, A64_R(0), r0), ctx);

	emit(A64_RET(A64_LR), ctx);
}

void dummy_tramp(void);

asm (
"	.pushsection .text, \"ax\", @progbits\n"
"	.type dummy_tramp, %function\n"
"dummy_tramp:\n"
"	mov x10, lr\n"
"	mov lr, x9\n"
"	ret x10\n"
"	.size dummy_tramp, .-dummy_tramp\n"
"	.popsection\n"
);

/*
 * Keep a local long-jump target in each JIT image. When no trampoline is
 * attached it points at dummy_tramp, which restores the saved LR and
 * returns to the instruction following the patch site.
 */
static void build_plt(struct jit_ctx *ctx)
{
	const u8 tmp = bpf2a64[TMP_REG_1];
	struct bpf_plt *plt = NULL;

	/* The embedded 64-bit target must be naturally aligned. */
	if ((ctx->idx + PLT_TARGET_OFFSET / sizeof(u32)) % 2)
		emit(A64_NOP, ctx);

	plt = (struct bpf_plt *)(ctx->image + ctx->idx);
	emit(A64_LDR64LIT(tmp, 2 * sizeof(u32)), ctx);
	emit(A64_BR(tmp), ctx);

	if (ctx->image)
		plt->target = (u64)&dummy_tramp;
}

/* JITs an eBPF instruction.
 * Returns:
 * 0  - successfully JITed an 8-byte eBPF instruction.
 * >0 - successfully JITed a 16-byte eBPF instruction.
 * <0 - failed to JIT.
 */
static int build_insn(const struct bpf_insn *insn, struct jit_ctx *ctx,
		      bool extra_pass)
{
	const u8 code = insn->code;
	const u8 dst = bpf2a64[insn->dst_reg];
	const u8 src = bpf2a64[insn->src_reg];
	const u8 tmp = bpf2a64[TMP_REG_1];
	const u8 tmp2 = bpf2a64[TMP_REG_2];
	const u8 tmp3 = bpf2a64[TMP_REG_3];
	const s16 off = insn->off;
	const s32 imm = insn->imm;
	const int i = insn - ctx->prog->insnsi;
	const bool is64 = BPF_CLASS(code) == BPF_ALU64;
	const bool isdw = BPF_SIZE(code) == BPF_DW;
	u8 jmp_cond, reg;
	s32 jmp_offset;

#define check_imm(bits, imm) do {				\
	if ((((imm) > 0) && ((imm) >> (bits))) ||		\
	    (((imm) < 0) && (~(imm) >> (bits)))) {		\
		pr_info("[%2d] imm=%d(0x%x) out of range\n",	\
			i, imm, imm);				\
		return -EINVAL;					\
	}							\
} while (0)
#define check_imm19(imm) check_imm(19, imm)
#define check_imm26(imm) check_imm(26, imm)

	switch (code) {
	/* dst = src */
	case BPF_ALU | BPF_MOV | BPF_X:
	case BPF_ALU64 | BPF_MOV | BPF_X:
		emit(A64_MOV(is64, dst, src), ctx);
		break;
	/* dst = dst OP src */
	case BPF_ALU | BPF_ADD | BPF_X:
	case BPF_ALU64 | BPF_ADD | BPF_X:
		emit(A64_ADD(is64, dst, dst, src), ctx);
		break;
	case BPF_ALU | BPF_SUB | BPF_X:
	case BPF_ALU64 | BPF_SUB | BPF_X:
		emit(A64_SUB(is64, dst, dst, src), ctx);
		break;
	case BPF_ALU | BPF_AND | BPF_X:
	case BPF_ALU64 | BPF_AND | BPF_X:
		emit(A64_AND(is64, dst, dst, src), ctx);
		break;
	case BPF_ALU | BPF_OR | BPF_X:
	case BPF_ALU64 | BPF_OR | BPF_X:
		emit(A64_ORR(is64, dst, dst, src), ctx);
		break;
	case BPF_ALU | BPF_XOR | BPF_X:
	case BPF_ALU64 | BPF_XOR | BPF_X:
		emit(A64_EOR(is64, dst, dst, src), ctx);
		break;
	case BPF_ALU | BPF_MUL | BPF_X:
	case BPF_ALU64 | BPF_MUL | BPF_X:
		emit(A64_MUL(is64, dst, dst, src), ctx);
		break;
	case BPF_ALU | BPF_DIV | BPF_X:
	case BPF_ALU64 | BPF_DIV | BPF_X:
	case BPF_ALU | BPF_MOD | BPF_X:
	case BPF_ALU64 | BPF_MOD | BPF_X:
	{
		const u8 r0 = bpf2a64[BPF_REG_0];

		/* if (src == 0) return 0 */
		jmp_offset = 3; /* skip ahead to else path */
		check_imm19(jmp_offset);
		emit(A64_CBNZ(is64, src, jmp_offset), ctx);
		emit(A64_MOVZ(1, r0, 0, 0), ctx);
		jmp_offset = epilogue_offset(ctx);
		check_imm26(jmp_offset);
		emit(A64_B(jmp_offset), ctx);
		/* else */
		switch (BPF_OP(code)) {
		case BPF_DIV:
			emit(A64_UDIV(is64, dst, dst, src), ctx);
			break;
		case BPF_MOD:
			emit(A64_UDIV(is64, tmp, dst, src), ctx);
			emit(A64_MUL(is64, tmp, tmp, src), ctx);
			emit(A64_SUB(is64, dst, dst, tmp), ctx);
			break;
		}
		break;
	}
	case BPF_ALU | BPF_LSH | BPF_X:
	case BPF_ALU64 | BPF_LSH | BPF_X:
		emit(A64_LSLV(is64, dst, dst, src), ctx);
		break;
	case BPF_ALU | BPF_RSH | BPF_X:
	case BPF_ALU64 | BPF_RSH | BPF_X:
		emit(A64_LSRV(is64, dst, dst, src), ctx);
		break;
	case BPF_ALU | BPF_ARSH | BPF_X:
	case BPF_ALU64 | BPF_ARSH | BPF_X:
		emit(A64_ASRV(is64, dst, dst, src), ctx);
		break;
	/* dst = -dst */
	case BPF_ALU | BPF_NEG:
	case BPF_ALU64 | BPF_NEG:
		emit(A64_NEG(is64, dst, dst), ctx);
		break;
	/* dst = BSWAP##imm(dst) */
	case BPF_ALU | BPF_END | BPF_FROM_LE:
	case BPF_ALU | BPF_END | BPF_FROM_BE:
#ifdef CONFIG_CPU_BIG_ENDIAN
		if (BPF_SRC(code) == BPF_FROM_BE)
			goto emit_bswap_uxt;
#else /* !CONFIG_CPU_BIG_ENDIAN */
		if (BPF_SRC(code) == BPF_FROM_LE)
			goto emit_bswap_uxt;
#endif
		switch (imm) {
		case 16:
			emit(A64_REV16(is64, dst, dst), ctx);
			/* zero-extend 16 bits into 64 bits */
			emit(A64_UXTH(is64, dst, dst), ctx);
			break;
		case 32:
			emit(A64_REV32(is64, dst, dst), ctx);
			/* upper 32 bits already cleared */
			break;
		case 64:
			emit(A64_REV64(dst, dst), ctx);
			break;
		}
		break;
emit_bswap_uxt:
		switch (imm) {
		case 16:
			/* zero-extend 16 bits into 64 bits */
			emit(A64_UXTH(is64, dst, dst), ctx);
			break;
		case 32:
			/* zero-extend 32 bits into 64 bits */
			emit(A64_UXTW(is64, dst, dst), ctx);
			break;
		case 64:
			/* nop */
			break;
		}
		break;
	/* dst = imm */
	case BPF_ALU | BPF_MOV | BPF_K:
	case BPF_ALU64 | BPF_MOV | BPF_K:
		emit_a64_mov_i(is64, dst, imm, ctx);
		break;
	/* dst = dst OP imm */
	case BPF_ALU | BPF_ADD | BPF_K:
	case BPF_ALU64 | BPF_ADD | BPF_K:
		emit_a64_mov_i(is64, tmp, imm, ctx);
		emit(A64_ADD(is64, dst, dst, tmp), ctx);
		break;
	case BPF_ALU | BPF_SUB | BPF_K:
	case BPF_ALU64 | BPF_SUB | BPF_K:
		emit_a64_mov_i(is64, tmp, imm, ctx);
		emit(A64_SUB(is64, dst, dst, tmp), ctx);
		break;
	case BPF_ALU | BPF_AND | BPF_K:
	case BPF_ALU64 | BPF_AND | BPF_K:
		emit_a64_mov_i(is64, tmp, imm, ctx);
		emit(A64_AND(is64, dst, dst, tmp), ctx);
		break;
	case BPF_ALU | BPF_OR | BPF_K:
	case BPF_ALU64 | BPF_OR | BPF_K:
		emit_a64_mov_i(is64, tmp, imm, ctx);
		emit(A64_ORR(is64, dst, dst, tmp), ctx);
		break;
	case BPF_ALU | BPF_XOR | BPF_K:
	case BPF_ALU64 | BPF_XOR | BPF_K:
		emit_a64_mov_i(is64, tmp, imm, ctx);
		emit(A64_EOR(is64, dst, dst, tmp), ctx);
		break;
	case BPF_ALU | BPF_MUL | BPF_K:
	case BPF_ALU64 | BPF_MUL | BPF_K:
		emit_a64_mov_i(is64, tmp, imm, ctx);
		emit(A64_MUL(is64, dst, dst, tmp), ctx);
		break;
	case BPF_ALU | BPF_DIV | BPF_K:
	case BPF_ALU64 | BPF_DIV | BPF_K:
		emit_a64_mov_i(is64, tmp, imm, ctx);
		emit(A64_UDIV(is64, dst, dst, tmp), ctx);
		break;
	case BPF_ALU | BPF_MOD | BPF_K:
	case BPF_ALU64 | BPF_MOD | BPF_K:
		emit_a64_mov_i(is64, tmp2, imm, ctx);
		emit(A64_UDIV(is64, tmp, dst, tmp2), ctx);
		emit(A64_MUL(is64, tmp, tmp, tmp2), ctx);
		emit(A64_SUB(is64, dst, dst, tmp), ctx);
		break;
	case BPF_ALU | BPF_LSH | BPF_K:
	case BPF_ALU64 | BPF_LSH | BPF_K:
		emit(A64_LSL(is64, dst, dst, imm), ctx);
		break;
	case BPF_ALU | BPF_RSH | BPF_K:
	case BPF_ALU64 | BPF_RSH | BPF_K:
		emit(A64_LSR(is64, dst, dst, imm), ctx);
		break;
	case BPF_ALU | BPF_ARSH | BPF_K:
	case BPF_ALU64 | BPF_ARSH | BPF_K:
		emit(A64_ASR(is64, dst, dst, imm), ctx);
		break;

	/* JUMP off */
	case BPF_JMP | BPF_JA:
		jmp_offset = bpf2a64_offset(i + off, i, ctx);
		check_imm26(jmp_offset);
		emit(A64_B(jmp_offset), ctx);
		break;
	/* IF (dst COND src) JUMP off */
	case BPF_JMP | BPF_JEQ | BPF_X:
	case BPF_JMP | BPF_JGT | BPF_X:
	case BPF_JMP | BPF_JLT | BPF_X:
	case BPF_JMP | BPF_JGE | BPF_X:
	case BPF_JMP | BPF_JLE | BPF_X:
	case BPF_JMP | BPF_JNE | BPF_X:
	case BPF_JMP | BPF_JSGT | BPF_X:
	case BPF_JMP | BPF_JSLT | BPF_X:
	case BPF_JMP | BPF_JSGE | BPF_X:
	case BPF_JMP | BPF_JSLE | BPF_X:
		emit(A64_CMP(1, dst, src), ctx);
emit_cond_jmp:
		jmp_offset = bpf2a64_offset(i + off, i, ctx);
		check_imm19(jmp_offset);
		switch (BPF_OP(code)) {
		case BPF_JEQ:
			jmp_cond = A64_COND_EQ;
			break;
		case BPF_JGT:
			jmp_cond = A64_COND_HI;
			break;
		case BPF_JLT:
			jmp_cond = A64_COND_CC;
			break;
		case BPF_JGE:
			jmp_cond = A64_COND_CS;
			break;
		case BPF_JLE:
			jmp_cond = A64_COND_LS;
			break;
		case BPF_JSET:
		case BPF_JNE:
			jmp_cond = A64_COND_NE;
			break;
		case BPF_JSGT:
			jmp_cond = A64_COND_GT;
			break;
		case BPF_JSLT:
			jmp_cond = A64_COND_LT;
			break;
		case BPF_JSGE:
			jmp_cond = A64_COND_GE;
			break;
		case BPF_JSLE:
			jmp_cond = A64_COND_LE;
			break;
		default:
			return -EFAULT;
		}
		emit(A64_B_(jmp_cond, jmp_offset), ctx);
		break;
	case BPF_JMP | BPF_JSET | BPF_X:
		emit(A64_TST(1, dst, src), ctx);
		goto emit_cond_jmp;
	/* IF (dst COND imm) JUMP off */
	case BPF_JMP | BPF_JEQ | BPF_K:
	case BPF_JMP | BPF_JGT | BPF_K:
	case BPF_JMP | BPF_JLT | BPF_K:
	case BPF_JMP | BPF_JGE | BPF_K:
	case BPF_JMP | BPF_JLE | BPF_K:
	case BPF_JMP | BPF_JNE | BPF_K:
	case BPF_JMP | BPF_JSGT | BPF_K:
	case BPF_JMP | BPF_JSLT | BPF_K:
	case BPF_JMP | BPF_JSGE | BPF_K:
	case BPF_JMP | BPF_JSLE | BPF_K:
		emit_a64_mov_i(1, tmp, imm, ctx);
		emit(A64_CMP(1, dst, tmp), ctx);
		goto emit_cond_jmp;
	case BPF_JMP | BPF_JSET | BPF_K:
		emit_a64_mov_i(1, tmp, imm, ctx);
		emit(A64_TST(1, dst, tmp), ctx);
		goto emit_cond_jmp;
	/* function call */
	case BPF_JMP | BPF_CALL:
	{
		const u8 r0 = bpf2a64[BPF_REG_0];
		bool func_addr_fixed;
		u64 func_addr;
		int ret;

		ret = bpf_jit_get_func_addr(ctx->prog, insn, extra_pass,
					    &func_addr, &func_addr_fixed);
		if (ret < 0)
			return ret;
		emit_addr_mov_i64(tmp, func_addr, ctx);
		emit(A64_BLR(tmp), ctx);
		emit(A64_MOV(1, r0, A64_R(0)), ctx);
		break;
	}
	/* tail call */
	case BPF_JMP | BPF_TAIL_CALL:
		if (emit_bpf_tail_call(ctx))
			return -EFAULT;
		break;
	/* function return */
	case BPF_JMP | BPF_EXIT:
		/* Optimization: when last instruction is EXIT,
		   simply fallthrough to epilogue. */
		if (i == ctx->prog->len - 1)
			break;
		jmp_offset = epilogue_offset(ctx);
		check_imm26(jmp_offset);
		emit(A64_B(jmp_offset), ctx);
		break;

	/* dst = imm64 */
	case BPF_LD | BPF_IMM | BPF_DW:
	{
		const struct bpf_insn insn1 = insn[1];
		u64 imm64;

		imm64 = (u64)insn1.imm << 32 | (u32)imm;
		emit_a64_mov_i64(dst, imm64, ctx);

		return 1;
	}

	/* LDX: dst = *(size *)(src + off) */
	case BPF_LDX | BPF_MEM | BPF_W:
	case BPF_LDX | BPF_MEM | BPF_H:
	case BPF_LDX | BPF_MEM | BPF_B:
	case BPF_LDX | BPF_MEM | BPF_DW:
		emit_a64_mov_i(1, tmp, off, ctx);
		switch (BPF_SIZE(code)) {
		case BPF_W:
			emit(A64_LDR32(dst, src, tmp), ctx);
			break;
		case BPF_H:
			emit(A64_LDRH(dst, src, tmp), ctx);
			break;
		case BPF_B:
			emit(A64_LDRB(dst, src, tmp), ctx);
			break;
		case BPF_DW:
			emit(A64_LDR64(dst, src, tmp), ctx);
			break;
		}
		break;

	/* ST: *(size *)(dst + off) = imm */
	case BPF_ST | BPF_MEM | BPF_W:
	case BPF_ST | BPF_MEM | BPF_H:
	case BPF_ST | BPF_MEM | BPF_B:
	case BPF_ST | BPF_MEM | BPF_DW:
		/* Load imm to a register then store it */
		emit_a64_mov_i(1, tmp2, off, ctx);
		emit_a64_mov_i(1, tmp, imm, ctx);
		switch (BPF_SIZE(code)) {
		case BPF_W:
			emit(A64_STR32(tmp, dst, tmp2), ctx);
			break;
		case BPF_H:
			emit(A64_STRH(tmp, dst, tmp2), ctx);
			break;
		case BPF_B:
			emit(A64_STRB(tmp, dst, tmp2), ctx);
			break;
		case BPF_DW:
			emit(A64_STR64(tmp, dst, tmp2), ctx);
			break;
		}
		break;

	/* STX: *(size *)(dst + off) = src */
	case BPF_STX | BPF_MEM | BPF_W:
	case BPF_STX | BPF_MEM | BPF_H:
	case BPF_STX | BPF_MEM | BPF_B:
	case BPF_STX | BPF_MEM | BPF_DW:
		emit_a64_mov_i(1, tmp, off, ctx);
		switch (BPF_SIZE(code)) {
		case BPF_W:
			emit(A64_STR32(src, dst, tmp), ctx);
			break;
		case BPF_H:
			emit(A64_STRH(src, dst, tmp), ctx);
			break;
		case BPF_B:
			emit(A64_STRB(src, dst, tmp), ctx);
			break;
		case BPF_DW:
			emit(A64_STR64(src, dst, tmp), ctx);
			break;
		}
		break;

	/* STX XADD: lock *(u32 *)(dst + off) += src */
	case BPF_STX | BPF_XADD | BPF_W:
	/* STX XADD: lock *(u64 *)(dst + off) += src */
	case BPF_STX | BPF_XADD | BPF_DW:
		if (!off) {
			reg = dst;
		} else {
			emit_a64_mov_i(1, tmp, off, ctx);
			emit(A64_ADD(1, tmp, tmp, dst), ctx);
			reg = tmp;
		}
		if (cpus_have_cap(ARM64_HAS_LSE_ATOMICS)) {
			emit(A64_STADD(isdw, reg, src), ctx);
		} else {
			emit(A64_LDXR(isdw, tmp2, reg), ctx);
			emit(A64_ADD(isdw, tmp2, tmp2, src), ctx);
			emit(A64_STXR(isdw, tmp2, reg, tmp3), ctx);
			jmp_offset = -3;
			check_imm19(jmp_offset);
			emit(A64_CBNZ(0, tmp3, jmp_offset), ctx);
		}
		break;

	/* R0 = ntohx(*(size *)(((struct sk_buff *)R6)->data + imm)) */
	case BPF_LD | BPF_ABS | BPF_W:
	case BPF_LD | BPF_ABS | BPF_H:
	case BPF_LD | BPF_ABS | BPF_B:
	/* R0 = ntohx(*(size *)(((struct sk_buff *)R6)->data + src + imm)) */
	case BPF_LD | BPF_IND | BPF_W:
	case BPF_LD | BPF_IND | BPF_H:
	case BPF_LD | BPF_IND | BPF_B:
	{
		const u8 r0 = bpf2a64[BPF_REG_0]; /* r0 = return value */
		const u8 r6 = bpf2a64[BPF_REG_6]; /* r6 = pointer to sk_buff */
		const u8 fp = bpf2a64[BPF_REG_FP];
		const u8 r1 = bpf2a64[BPF_REG_1]; /* r1: struct sk_buff *skb */
		const u8 r2 = bpf2a64[BPF_REG_2]; /* r2: int k */
		const u8 r3 = bpf2a64[BPF_REG_3]; /* r3: unsigned int size */
		const u8 r4 = bpf2a64[BPF_REG_4]; /* r4: void *buffer */
		const u8 r5 = bpf2a64[BPF_REG_5]; /* r5: void *(*func)(...) */
		int size;

		emit(A64_MOV(1, r1, r6), ctx);
		emit_a64_mov_i(0, r2, imm, ctx);
		if (BPF_MODE(code) == BPF_IND)
			emit(A64_ADD(0, r2, r2, src), ctx);
		switch (BPF_SIZE(code)) {
		case BPF_W:
			size = 4;
			break;
		case BPF_H:
			size = 2;
			break;
		case BPF_B:
			size = 1;
			break;
		default:
			return -EINVAL;
		}
		emit_a64_mov_i64(r3, size, ctx);
		emit(A64_SUB_I(1, r4, fp, ctx->stack_size), ctx);
		emit_a64_mov_i64(r5, (unsigned long)bpf_load_pointer, ctx);
		emit(A64_BLR(r5), ctx);
		emit(A64_MOV(1, r0, A64_R(0)), ctx);

		jmp_offset = epilogue_offset(ctx);
		check_imm19(jmp_offset);
		emit(A64_CBZ(1, r0, jmp_offset), ctx);
		emit(A64_MOV(1, r5, r0), ctx);
		switch (BPF_SIZE(code)) {
		case BPF_W:
			emit(A64_LDR32(r0, r5, A64_ZR), ctx);
#ifndef CONFIG_CPU_BIG_ENDIAN
			emit(A64_REV32(0, r0, r0), ctx);
#endif
			break;
		case BPF_H:
			emit(A64_LDRH(r0, r5, A64_ZR), ctx);
#ifndef CONFIG_CPU_BIG_ENDIAN
			emit(A64_REV16(0, r0, r0), ctx);
#endif
			break;
		case BPF_B:
			emit(A64_LDRB(r0, r5, A64_ZR), ctx);
			break;
		}
		break;
	}
	default:
		pr_err_once("unknown opcode %02x\n", code);
		return -EINVAL;
	}

	return 0;
}

static int build_body(struct jit_ctx *ctx, bool extra_pass)
{
	const struct bpf_prog *prog = ctx->prog;
	int i;

	for (i = 0; i < prog->len; i++) {
		const struct bpf_insn *insn = &prog->insnsi[i];
		int ret;

		ret = build_insn(insn, ctx, extra_pass);
		if (ret > 0) {
			i++;
			if (ctx->image == NULL)
				ctx->offset[i] = ctx->idx;
			continue;
		}
		if (ctx->image == NULL)
			ctx->offset[i] = ctx->idx;
		if (ret)
			return ret;
	}

	return 0;
}

static int validate_code(struct jit_ctx *ctx)
{
	int i;

	for (i = 0; i < ctx->idx; i++) {
		u32 a64_insn = le32_to_cpu(ctx->image[i]);

		if (a64_insn == AARCH64_BREAK_FAULT)
			return -1;
	}

	return 0;
}

static inline void bpf_flush_icache(void *start, void *end)
{
	flush_icache_range((unsigned long)start, (unsigned long)end);
}

struct arm64_jit_data {
	struct bpf_binary_header *header;
	u8 *image;
	struct jit_ctx ctx;
};

struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog)
{
	struct bpf_prog *tmp, *orig_prog = prog;
	struct bpf_binary_header *header;
	struct arm64_jit_data *jit_data;
	bool tmp_blinded = false;
	bool extra_pass = false;
	struct jit_ctx ctx;
	int image_size, prog_size;
	u8 *image_ptr;

	if (!prog->jit_requested)
		return orig_prog;

	tmp = bpf_jit_blind_constants(prog);
	/* If blinding was requested and we failed during blinding,
	 * we must fall back to the interpreter.
	 */
	if (IS_ERR(tmp))
		return orig_prog;
	if (tmp != prog) {
		tmp_blinded = true;
		prog = tmp;
	}

	jit_data = prog->aux->jit_data;
	if (!jit_data) {
		jit_data = kzalloc(sizeof(*jit_data), GFP_KERNEL);
		if (!jit_data) {
			prog = orig_prog;
			goto out;
		}
		prog->aux->jit_data = jit_data;
	}
	if (jit_data->ctx.offset) {
		ctx = jit_data->ctx;
		image_ptr = jit_data->image;
		header = jit_data->header;
		extra_pass = true;
		prog_size = sizeof(u32) * ctx.idx;
		image_size = prog_size + PLT_TARGET_SIZE;
		goto skip_init_ctx;
	}
	memset(&ctx, 0, sizeof(ctx));
	ctx.prog = prog;

	ctx.offset = kcalloc(prog->len, sizeof(int), GFP_KERNEL);
	if (ctx.offset == NULL) {
		prog = orig_prog;
		goto out_off;
	}

	/* 1. Initial fake pass to compute ctx->idx. */

	/* Fake pass to fill in ctx->offset. */
	if (build_body(&ctx, extra_pass)) {
		prog = orig_prog;
		goto out;
	}

	if (build_prologue(&ctx)) {
		prog = orig_prog;
		goto out_off;
	}

	ctx.epilogue_offset = ctx.idx;
	build_epilogue(&ctx);
	build_plt(&ctx);

	/* Include the inline PLT literal, but exclude it from jited_len below. */
	prog_size = sizeof(u32) * ctx.idx;
	image_size = prog_size + PLT_TARGET_SIZE;
	header = bpf_jit_binary_alloc(image_size, &image_ptr,
				      sizeof(u32), jit_fill_hole);
	if (header == NULL) {
		prog = orig_prog;
		goto out_off;
	}

	/* 2. Now, the actual pass. */

	ctx.image = (__le32 *)image_ptr;
skip_init_ctx:
	ctx.idx = 0;

	build_prologue(&ctx);

	if (build_body(&ctx, extra_pass)) {
		bpf_jit_binary_free(header);
		prog = orig_prog;
		goto out_off;
	}

	build_epilogue(&ctx);
	build_plt(&ctx);
	prog_size = sizeof(u32) * ctx.idx;

	/* 3. Extra pass to validate JITed code. */
	if (validate_code(&ctx)) {
		bpf_jit_binary_free(header);
		prog = orig_prog;
		goto out_off;
	}

	/* And we're done. */
	if (bpf_jit_enable > 1)
		bpf_jit_dump(prog->len, prog_size, 2, ctx.image);

	bpf_flush_icache(header, ctx.image + ctx.idx);

	if (!prog->is_func || extra_pass) {
		if (extra_pass && ctx.idx != jit_data->ctx.idx) {
			pr_err_once("multi-func JIT bug %d != %d\n",
				    ctx.idx, jit_data->ctx.idx);
			bpf_jit_binary_free(header);
			prog->bpf_func = NULL;
			prog->jited = 0;
			prog->jited_len = 0;
			goto out_off;
		}
		bpf_jit_binary_lock_ro(header);
	} else {
		jit_data->ctx = ctx;
		jit_data->image = image_ptr;
		jit_data->header = header;
	}
	prog->bpf_func = (void *)ctx.image;
	prog->jited = 1;
	prog->jited_len = prog_size;

	if (!prog->is_func || extra_pass) {
out_off:
		kfree(ctx.offset);
		kfree(jit_data);
		prog->aux->jit_data = NULL;
	}
out:
	if (tmp_blinded)
		bpf_jit_prog_release_other(prog, prog == orig_prog ?
					   tmp : orig_prog);
	return prog;
}


static bool is_long_jump(void *ip, void *target)
{
	long offset;

	if (!target)
		return false;

	offset = (long)target - (long)ip;
	return offset < -SZ_128M || offset >= SZ_128M;
}

static int gen_branch_or_nop(enum aarch64_insn_branch_type type, void *ip,
			     void *addr, void *plt, u32 *insn)
{
	void *target;

	if (!addr) {
		*insn = aarch64_insn_gen_nop();
		return 0;
	}

	target = is_long_jump(ip, addr) ? plt : addr;
	*insn = aarch64_insn_gen_branch_imm((unsigned long)ip,
					    (unsigned long)target, type);

	return *insn != AARCH64_BREAK_FAULT ? 0 : -EFAULT;
}

#ifdef CONFIG_BPF_TRAMPOLINE_NATIVE
/*
 * Replace a 16-byte, four-NOP patchpoint at a native kernel function entry.
 * The generated MOVN/MOVK/BR sequence is independent of branch distance, so
 * it can reach a trampoline allocated in the BPF JIT region.
 */
static void bpf_trampoline_gen_native_branch(void *target, u32 insns[4])
{
	u64 addr = (u64)target;
	int i;

	if (!target) {
		for (i = 0; i < BPF_TRAMPOLINE_NATIVE_PATCH_INSNS; i++)
			insns[i] = aarch64_insn_gen_nop();
		return;
	}

	insns[0] = A64_MOVN(1, A64_R(10), (~addr) & 0xffff, 0);
	insns[1] = A64_MOVK(1, A64_R(10), (addr >> 16) & 0xffff, 16);
	insns[2] = A64_MOVK(1, A64_R(10), (addr >> 32) & 0xffff, 32);
	insns[3] = A64_BR(A64_R(10));
}

static int bpf_arch_text_poke_native(void *ip,
				     enum bpf_text_poke_type poke_type,
				     void *old_addr, void *new_addr)
{
	void *addrs[BPF_TRAMPOLINE_NATIVE_PATCH_INSNS];
	char namebuf[KSYM_NAME_LEN];
	char *modname = NULL;
	unsigned long size = 0, offset = 0;
	const char *name;
	u32 expected[BPF_TRAMPOLINE_NATIVE_PATCH_INSNS];
	u32 replacement[BPF_TRAMPOLINE_NATIVE_PATCH_INSNS];
	u32 replaced;
	int i, ret = 0;

	if (poke_type != BPF_MOD_CALL ||
	    !IS_ALIGNED((unsigned long)ip, AARCH64_INSN_SIZE))
		return -EINVAL;

	/* This first-stage backend only patches core-kernel function entries. */
	name = kallsyms_lookup((unsigned long)ip, &size, &offset,
			       &modname, namebuf);
	if (!name || modname || offset ||
	    size < BPF_TRAMPOLINE_NATIVE_PATCH_INSNS * AARCH64_INSN_SIZE)
		return -ENOTSUPP;

	bpf_trampoline_gen_native_branch(old_addr, expected);
	bpf_trampoline_gen_native_branch(new_addr, replacement);
	for (i = 0; i < BPF_TRAMPOLINE_NATIVE_PATCH_INSNS; i++)
		addrs[i] = ip + i * AARCH64_INSN_SIZE;

	mutex_lock(&text_mutex);
	for (i = 0; i < BPF_TRAMPOLINE_NATIVE_PATCH_INSNS; i++) {
		ret = aarch64_insn_read(addrs[i], &replaced);
		if (ret || replaced != expected[i]) {
			ret = -EFAULT;
			goto out;
		}
	}

	if (memcmp(expected, replacement, sizeof(expected)))
		ret = aarch64_insn_patch_text(addrs, replacement,
				      BPF_TRAMPOLINE_NATIVE_PATCH_INSNS);
out:
	mutex_unlock(&text_mutex);
	return ret;
}
#endif

/*
 * Replace the branch instruction at a BPF JIT patch site. Long jumps from
 * a BPF program use its inline PLT because module/vmalloc allocations can
 * be farther apart than the AArch64 +/-128 MiB branch range.
 */
int bpf_arch_text_poke(void *ip, enum bpf_text_poke_type poke_type,
		       void *old_addr, void *new_addr)
{
	int ret;
	u32 old_insn, new_insn, replaced;
	struct bpf_plt *plt = NULL;
	unsigned long size = 0, offset = ~0UL;
	enum aarch64_insn_branch_type branch_type;
	char namebuf[KSYM_NAME_LEN];
	void *image;
	u64 plt_target = 0;
	bool poking_bpf_entry;

	if (!__bpf_address_lookup((unsigned long)ip, &size, &offset, namebuf)) {
#ifdef CONFIG_BPF_TRAMPOLINE_NATIVE
		return bpf_arch_text_poke_native(ip, poke_type, old_addr, new_addr);
#else
		return -ENOTSUPP;
#endif
	}

	image = ip - offset;
	poking_bpf_entry = (offset == 0);
	if (poking_bpf_entry) {
		plt = image + size - PLT_TARGET_OFFSET;
		ip = image + POKE_OFFSET * sizeof(u32);
	}

	if (WARN_ON((is_long_jump(ip, new_addr) ||
		     is_long_jump(ip, old_addr)) && !poking_bpf_entry))
		return -EINVAL;

	branch_type = poke_type == BPF_MOD_CALL ?
		AARCH64_INSN_BRANCH_LINK : AARCH64_INSN_BRANCH_NOLINK;
	if (gen_branch_or_nop(branch_type, ip, old_addr, plt, &old_insn) < 0)
		return -EFAULT;
	if (gen_branch_or_nop(branch_type, ip, new_addr, plt, &new_insn) < 0)
		return -EFAULT;

	if (is_long_jump(ip, new_addr))
		plt_target = (u64)new_addr;
	else if (is_long_jump(ip, old_addr))
		plt_target = (u64)&dummy_tramp;

	if (plt_target) {
		unsigned long page = (unsigned long)&plt->target & PAGE_MASK;

		if (set_memory_rw(page, 1))
			return -EFAULT;
		WRITE_ONCE(plt->target, plt_target);
		if (set_memory_ro(page, 1))
			return -EFAULT;
	}

	if (old_insn == new_insn)
		return 0;

	mutex_lock(&text_mutex);
	if (aarch64_insn_read(ip, &replaced)) {
		ret = -EFAULT;
		goto out;
	}
	if (replaced != old_insn) {
		ret = -EFAULT;
		goto out;
	}

	ret = aarch64_insn_patch_text_nosync(ip, new_insn);
out:
	mutex_unlock(&text_mutex);
	return ret;
}

#ifdef CONFIG_CFI_CLANG
bool arch_bpf_jit_check_func(const struct bpf_prog *prog)
{
	const uintptr_t func = (const uintptr_t)prog->bpf_func;

	/*
	 * bpf_func must be correctly aligned and within the correct region.
	 * module_alloc places JIT code in the module region, unless
	 * ARM64_MODULE_PLTS is enabled, in which case we might end up using
	 * the vmalloc region too.
	 */
	if (unlikely(!IS_ALIGNED(func, sizeof(u32))))
		return false;

	if (IS_ENABLED(CONFIG_ARM64_MODULE_PLTS) &&
			is_vmalloc_addr(prog->bpf_func))
		return true;

	return (func >= MODULES_VADDR && func < MODULES_END);
}
#endif


/*
 * Initial ARM64 BPF trampoline generator.
 *
 * This stage deliberately supports scalar/pointer fentry arguments only.
 * Native kernel-function attach still requires the matching ftrace direct-call
 * adapter; bpf_arch_text_poke() below this layer only patches BPF JIT images.
 */
static void emit_trampoline_call(struct jit_ctx *ctx, u64 addr)
{
	emit_addr_mov_i64(A64_R(10), addr, ctx);
	emit(A64_BLR(A64_R(10)), ctx);
}

static int emit_bpf_trampoline(struct jit_ctx *ctx,
			       struct btf_func_model *m, u32 flags,
			       struct bpf_prog **fentry_progs,
			       int fentry_cnt, int fexit_cnt, void *orig_call)
{
	bool native_entry = flags & BPF_TRAMP_F_NATIVE_ENTRY;
	int args_off = 0;
	int regs_off;
	int stack_size;
	int i;

	if (native_entry) {
		if (!IS_ENABLED(CONFIG_BPF_TRAMPOLINE_NATIVE) ||
		    flags != (BPF_TRAMP_F_RESTORE_REGS |
			     BPF_TRAMP_F_NATIVE_ENTRY) || fexit_cnt || !orig_call)
			return -ENOTSUPP;
	} else if (flags != BPF_TRAMP_F_RESTORE_REGS || fexit_cnt) {
		return -ENOTSUPP;
	}
	if (fentry_cnt > BPF_MAX_TRAMP_PROGS)
		return -E2BIG;
	if (fentry_cnt && !fentry_progs)
		return -EINVAL;
	if (m->nr_args > 8)
		return -ENOTSUPP;
	/* Aggregate arguments can consume multiple AAPCS64 registers. */
	for (i = 0; i < m->nr_args; i++)
		if (m->arg_size[i] > sizeof(u64))
			return -ENOTSUPP;

	/*
	 * The patch site saves the original caller LR in x9, then branches
	 * here with BL. Preserve both return addresses and maintain a 16-byte
	 * aligned stack while the BPF programs execute.
	 */
	emit(A64_PUSH(A64_FP, A64_R(9), A64_SP), ctx);
	emit(A64_MOV(1, A64_FP, A64_SP), ctx);
	emit(A64_PUSH(A64_FP, A64_LR, A64_SP), ctx);
	emit(A64_MOV(1, A64_FP, A64_SP), ctx);

	/* x8 is an ABI hidden-return pointer and must survive native hooks too. */
	regs_off = (native_entry ? 9 : m->nr_args) * sizeof(u64);
	stack_size = round_up(regs_off + 2 * sizeof(u64), 16);
	emit(A64_SUB_I(1, A64_SP, A64_SP, stack_size), ctx);

	if (native_entry) {
		for (i = 0; i < 9; i++)
			emit(A64_STR64I(i, A64_SP, args_off + i * sizeof(u64)), ctx);
	} else {
		for (i = 0; i < m->nr_args; i++)
			emit(A64_STR64I(i, A64_SP, args_off + i * sizeof(u64)), ctx);
	}
	emit(A64_STR64I(A64_R(19), A64_SP, regs_off), ctx);
	emit(A64_STR64I(A64_R(20), A64_SP, regs_off + sizeof(u64)), ctx);

	for (i = 0; i < fentry_cnt; i++) {
		struct bpf_prog *prog = fentry_progs[i];

		if (!prog || !prog->bpf_func)
			return -EINVAL;

		emit_addr_mov_i64(A64_R(19), (u64)prog, ctx);
		emit_trampoline_call(ctx, (u64)__bpf_prog_enter);
		emit(A64_MOV(1, A64_R(20), A64_R(0)), ctx);

		/* arg1: pointer to the saved BTF argument array */
		emit(A64_MOV(1, A64_R(0), A64_SP), ctx);
		if (!prog->jited) {
			emit_a64_mov_i64(A64_R(10),
					 offsetof(struct bpf_prog, insnsi), ctx);
			emit(A64_LDR64(A64_R(1), A64_R(19), A64_R(10)), ctx);
		}
		emit_a64_mov_i64(A64_R(10),
				offsetof(struct bpf_prog, bpf_func), ctx);
		emit(A64_LDR64(A64_R(10), A64_R(19), A64_R(10)), ctx);
		emit(A64_BLR(A64_R(10)), ctx);

		/* __bpf_prog_exit(prog, start) */
		emit(A64_MOV(1, A64_R(0), A64_R(19)), ctx);
		emit(A64_MOV(1, A64_R(1), A64_R(20)), ctx);
		emit_trampoline_call(ctx, (u64)__bpf_prog_exit);
	}

	if (native_entry) {
		for (i = 0; i < 9; i++)
			emit(A64_LDR64I(i, A64_SP, args_off + i * sizeof(u64)), ctx);
	} else {
		for (i = 0; i < m->nr_args; i++)
			emit(A64_LDR64I(i, A64_SP, args_off + i * sizeof(u64)), ctx);
	}
	emit(A64_LDR64I(A64_R(19), A64_SP, regs_off), ctx);
	emit(A64_LDR64I(A64_R(20), A64_SP, regs_off + sizeof(u64)), ctx);

	emit(A64_MOV(1, A64_SP, A64_FP), ctx);
	emit(A64_POP(A64_FP, A64_LR, A64_SP), ctx);
	emit(A64_POP(A64_FP, A64_R(9), A64_SP), ctx);
	if (native_entry) {
		/* Continue after the reserved NOP patchpoint without linking. */
		emit_addr_mov_i64(A64_R(10),
				  (u64)orig_call +
				  BPF_TRAMPOLINE_NATIVE_PATCH_INSNS *
				  AARCH64_INSN_SIZE, ctx);
		emit(A64_BR(A64_R(10)), ctx);
	} else {
		emit(A64_MOV(1, A64_R(10), A64_LR), ctx);
		emit(A64_MOV(1, A64_LR, A64_R(9)), ctx);
		emit(A64_RET(A64_R(10)), ctx);
	}

	/*
	 * Each half of the trampoline page is a separate image. Check the
	 * generated size in the sizing pass before writing executable memory.
	 */
	if (ctx->idx * sizeof(u32) > PAGE_SIZE / 2)
		return -E2BIG;

	return 0;
}

int arch_prepare_bpf_trampoline(void *image, struct btf_func_model *m,
				u32 flags, struct bpf_prog **fentry_progs,
				int fentry_cnt, struct bpf_prog **fexit_progs,
				int fexit_cnt, void *orig_call)
{
	struct jit_ctx ctx = {
		.prog = NULL,
		.idx = 0,
		.epilogue_offset = 0,
		.offset = NULL,
		.image = NULL,
		.stack_size = 0,
	};
	int expected_idx;
	int err;

	if (!image || !m || fentry_cnt < 0 || fexit_cnt < 0)
		return -EINVAL;

	/*
	 * First size the trampoline without writing it. The image is split
	 * into two halves by the generic manager, so writing first and checking
	 * the size afterward could corrupt the alternate image.
	 */
	err = emit_bpf_trampoline(&ctx, m, flags, fentry_progs,
				  fentry_cnt, fexit_cnt, orig_call);
	if (err)
		return err;
	expected_idx = ctx.idx;

	ctx.image = image;
	ctx.idx = 0;
	err = emit_bpf_trampoline(&ctx, m, flags, fentry_progs,
				  fentry_cnt, fexit_cnt, orig_call);
	if (err)
		return err;
	if (WARN_ON_ONCE(ctx.idx != expected_idx))
		return -EFAULT;

	/* Make the generated trampoline visible to the instruction cache. */
	flush_icache_range((unsigned long)image,
			   (unsigned long)image + ctx.idx * sizeof(u32));
	return 0;
}
