/*
 * Native ARM64 BPF trampoline runtime selftest.
 *
 * This test requires CONFIG_BPF_TRAMPOLINE_NATIVE, CONFIG_DEBUG_INFO_BTF,
 * root privileges, and /sys/kernel/btf/vmlinux. It attaches fentry and fexit
 * programs to the getpid syscall implementation and checks independent map
 * counters after invoking the syscall. It is intended for an experimental
 * kernel built specifically for runtime validation, not a production kernel.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef BPF_PSEUDO_MAP_FD
#error "linux/bpf.h must define BPF_PSEUDO_MAP_FD"
#endif

#define BTF_SYSFS_PATH "/sys/kernel/btf/vmlinux"
#define VERIFIER_LOG_SIZE (64 * 1024)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct btf_blob {
	void *data;
	size_t size;
	const unsigned char *types;
	size_t types_len;
	const char *strings;
	size_t strings_len;
};

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr)
{
	return (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int read_file(const char *path, void **data_out, size_t *size_out)
{
	int fd;
	void *data = NULL;
	size_t used = 0, capacity = 1024 * 1024;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	data = malloc(capacity);
	if (!data) {
		close(fd);
		return -ENOMEM;
	}
	for (;;) {
		ssize_t n;

		if (used == capacity) {
			size_t new_capacity = capacity * 2;
			void *new_data;

			if (new_capacity < capacity) {
				free(data);
				close(fd);
				return -EOVERFLOW;
			}
			new_data = realloc(data, new_capacity);
			if (!new_data) {
				free(data);
				close(fd);
				return -ENOMEM;
			}
			data = new_data;
			capacity = new_capacity;
		}
		n = read(fd, (char *)data + used, capacity - used);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			{
				int err = -errno;
				free(data);
				close(fd);
				return err;
			}
		}
		if (!n)
			break;
		used += (size_t)n;
	}
	close(fd);
	*data_out = data;
	*size_out = used;
	return 0;
}

static int load_btf_blob(struct btf_blob *blob)
{
	struct btf_header *hdr;
	size_t base;
	int err;

	memset(blob, 0, sizeof(*blob));
	err = read_file(BTF_SYSFS_PATH, &blob->data, &blob->size);
	if (err)
		return err;
	if (blob->size < sizeof(*hdr)) {
		err = -EINVAL;
		goto fail;
	}
	hdr = blob->data;
	if (hdr->magic != BTF_MAGIC || hdr->version != BTF_VERSION) {
		err = -EINVAL;
		goto fail;
	}
	if (hdr->hdr_len < sizeof(*hdr) || hdr->hdr_len > blob->size) {
		err = -EINVAL;
		goto fail;
	}
	base = hdr->hdr_len;
	if (hdr->type_off > blob->size - base ||
	    hdr->type_len > blob->size - base - hdr->type_off ||
	    hdr->str_off > blob->size - base ||
	    hdr->str_len > blob->size - base - hdr->str_off) {
		err = -EINVAL;
		goto fail;
	}
	blob->types = (const unsigned char *)blob->data + base + hdr->type_off;
	blob->types_len = hdr->type_len;
	blob->strings = (const char *)blob->data + base + hdr->str_off;
	blob->strings_len = hdr->str_len;
	return 0;
fail:
	free(blob->data);
	memset(blob, 0, sizeof(*blob));
	return err;
}

static int btf_string_equals(const struct btf_blob *blob, uint32_t off,
			     const char *name)
{
	const char *str;
	size_t left;

	if (off >= blob->strings_len)
		return 0;
	str = blob->strings + off;
	left = blob->strings_len - off;
	if (!memchr(str, '\0', left))
		return 0;
	return strcmp(str, name) == 0;
}

/*
 * BTF type IDs are one-based and follow the records in the type section.
 * This parser handles the BTF kinds supported by the Linux 4.9 backport.
 */
static int find_global_function_id(const struct btf_blob *blob,
				   const char *name, uint32_t *id_out)
{
	size_t off = 0;
	uint32_t id = 1;

	while (off + sizeof(struct btf_type) <= blob->types_len) {
		const struct btf_type *t =
			(const struct btf_type *)(blob->types + off);
		uint32_t kind = BTF_INFO_KIND(t->info);
		uint32_t vlen = BTF_INFO_VLEN(t->info);
		size_t extra = 0, next;

		if (kind == BTF_KIND_FUNC && vlen == BTF_FUNC_GLOBAL &&
		    btf_string_equals(blob, t->name_off, name)) {
			*id_out = id;
			return 0;
		}

		switch (kind) {
		case BTF_KIND_INT:
			extra = sizeof(uint32_t);
			break;
		case BTF_KIND_ARRAY:
			extra = sizeof(struct btf_array);
			break;
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			extra = (size_t)vlen * sizeof(struct btf_member);
			break;
		case BTF_KIND_ENUM:
			extra = (size_t)vlen * sizeof(struct btf_enum);
			break;
		case BTF_KIND_FUNC_PROTO:
			extra = (size_t)vlen * sizeof(struct btf_param);
			break;
		case BTF_KIND_VAR:
			extra = sizeof(struct btf_var);
			break;
		case BTF_KIND_DATASEC:
			extra = (size_t)vlen * sizeof(struct btf_var_secinfo);
			break;
		case BTF_KIND_UNKN:
		case BTF_KIND_PTR:
		case BTF_KIND_FWD:
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_FUNC:
			break;
		default:
			fprintf(stderr,
				"Unsupported BTF kind %u while parsing vmlinux BTF\n",
				kind);
			return -EOPNOTSUPP;
		}
		if (extra > blob->types_len - off - sizeof(*t))
			return -EINVAL;
		next = off + sizeof(*t) + extra;
		if (next <= off || next > blob->types_len)
			return -EINVAL;
		off = next;
		id++;
	}
	return -ENOENT;
}

static int find_getpid_btf_id(uint32_t *id_out, const char **name_out)
{
	static const char *const candidates[] = {
		"sys_getpid",
		"__arm64_sys_getpid",
		"SyS_getpid",
	};
	struct btf_blob blob;
	size_t i;
	int err = load_btf_blob(&blob);

	if (err)
		return err;
	for (i = 0; i < ARRAY_SIZE(candidates); i++) {
		err = find_global_function_id(&blob, candidates[i], id_out);
		if (!err) {
			*name_out = candidates[i];
			free(blob.data);
			return 0;
		}
		if (err != -ENOENT) {
			free(blob.data);
			return err;
		}
	}
	free(blob.data);
	return -ENOENT;
}

static int create_counter_map(void)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(uint64_t);
	attr.max_entries = 2;
	return sys_bpf(BPF_MAP_CREATE, &attr);
}

static int load_counter_prog(int map_fd, uint32_t btf_id,
			     enum bpf_attach_type attach_type,
			     uint32_t counter_index)
{
	struct bpf_insn insns[12];
	union bpf_attr attr;
	char verifier_log[VERIFIER_LOG_SIZE];
	static const char license[] = "GPL";
	int fd;

	memset(insns, 0, sizeof(insns));
	/* R1 = map_fd. The next instruction is the high half of the pseudo-load. */
	insns[0].code = BPF_LD | BPF_DW | BPF_IMM;
	insns[0].dst_reg = BPF_REG_1;
	insns[0].src_reg = BPF_PSEUDO_MAP_FD;
	insns[0].imm = map_fd;

	/* Store the counter key on the BPF stack for map_lookup_elem(). */
	insns[2].code = BPF_ST | BPF_MEM | BPF_W;
	insns[2].dst_reg = BPF_REG_10;
	insns[2].off = -4;
	insns[2].imm = (int32_t)counter_index;
	insns[3].code = BPF_ALU64 | BPF_MOV | BPF_X;
	insns[3].dst_reg = BPF_REG_2;
	insns[3].src_reg = BPF_REG_10;
	insns[4].code = BPF_ALU64 | BPF_ADD | BPF_K;
	insns[4].dst_reg = BPF_REG_2;
	insns[4].imm = -4;
	insns[5].code = BPF_JMP | BPF_CALL;
	insns[5].imm = BPF_FUNC_map_lookup_elem;

	/* if (R0 == NULL) goto return; */
	insns[6].code = BPF_JMP | BPF_JEQ | BPF_K;
	insns[6].dst_reg = BPF_REG_0;
	insns[6].off = 3;
	insns[7].code = BPF_LDX | BPF_MEM | BPF_DW;
	insns[7].dst_reg = BPF_REG_1;
	insns[7].src_reg = BPF_REG_0;
	insns[8].code = BPF_ALU64 | BPF_ADD | BPF_K;
	insns[8].dst_reg = BPF_REG_1;
	insns[8].imm = 1;
	insns[9].code = BPF_STX | BPF_MEM | BPF_DW;
	insns[9].dst_reg = BPF_REG_0;
	insns[9].src_reg = BPF_REG_1;
	insns[10].code = BPF_ALU64 | BPF_MOV | BPF_K;
	insns[10].dst_reg = BPF_REG_0;
	insns[10].imm = 0;
	insns[11].code = BPF_JMP | BPF_EXIT;

	memset(&attr, 0, sizeof(attr));
	memset(verifier_log, 0, sizeof(verifier_log));
	attr.prog_type = BPF_PROG_TYPE_TRACING;
	attr.insn_cnt = (uint32_t)ARRAY_SIZE(insns);
	attr.insns = (uint64_t)(uintptr_t)insns;
	attr.license = (uint64_t)(uintptr_t)license;
	attr.log_level = 1;
	attr.log_size = sizeof(verifier_log);
	attr.log_buf = (uint64_t)(uintptr_t)verifier_log;
	attr.expected_attach_type = attach_type;
	attr.attach_btf_id = btf_id;
	if (attach_type == BPF_TRACE_FENTRY)
		snprintf(attr.prog_name, sizeof(attr.prog_name), "native_fentry");
	else
		snprintf(attr.prog_name, sizeof(attr.prog_name), "native_fexit");

	fd = sys_bpf(BPF_PROG_LOAD, &attr);
	if (fd < 0) {
		fprintf(stderr, "BPF_PROG_LOAD (%s) failed: %s\n",
			attach_type == BPF_TRACE_FENTRY ? "fentry" : "fexit",
			strerror(errno));
		if (verifier_log[0])
			fprintf(stderr, "Verifier log:\n%s\n", verifier_log);
		return -1;
	}
	return fd;
}

static int attach_tracing_prog(int prog_fd)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.raw_tracepoint.prog_fd = (uint32_t)prog_fd;
	return sys_bpf(BPF_RAW_TRACEPOINT_OPEN, &attr);
}

static int lookup_counter(int map_fd, uint32_t index, uint64_t *value)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = (uint32_t)map_fd;
	attr.key = (uint64_t)(uintptr_t)&index;
	attr.value = (uint64_t)(uintptr_t)value;
	return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr);
}

int main(void)
{
	uint32_t btf_id;
	const char *target_name = NULL;
	uint64_t fentry_count = 0, fexit_count = 0;
	int map_fd = -1, fentry_prog = -1, fexit_prog = -1;
	int fentry_link = -1, fexit_link = -1;
	int result = 1;

	if (geteuid() != 0) {
		fprintf(stderr, "Run this native BPF trampoline selftest as root.\n");
		return 4;
	}
	if (access(BTF_SYSFS_PATH, R_OK)) {
		fprintf(stderr, "Missing %s; the kernel must expose vmlinux BTF.\n",
			BTF_SYSFS_PATH);
		return 4;
	}
	if (find_getpid_btf_id(&btf_id, &target_name)) {
		fprintf(stderr, "Could not find a supported global getpid syscall BTF function.\n");
		return 4;
	}
	printf("Using BTF function %s (id %u).\n", target_name, btf_id);

	map_fd = create_counter_map();
	if (map_fd < 0) {
		perror("BPF_MAP_CREATE");
		goto out;
	}
	fentry_prog = load_counter_prog(map_fd, btf_id, BPF_TRACE_FENTRY, 0);
	if (fentry_prog < 0)
		goto out;
	fexit_prog = load_counter_prog(map_fd, btf_id, BPF_TRACE_FEXIT, 1);
	if (fexit_prog < 0)
		goto out;

	fentry_link = attach_tracing_prog(fentry_prog);
	if (fentry_link < 0) {
		perror("attach native fentry");
		goto out;
	}
	fexit_link = attach_tracing_prog(fexit_prog);
	if (fexit_link < 0) {
		perror("attach native fexit");
		goto out;
	}

	/* Invoke the syscall after both programs have been attached. */
	if (syscall(SYS_getpid) < 0) {
		perror("getpid syscall");
		goto out;
	}
	if (lookup_counter(map_fd, 0, &fentry_count) < 0 ||
	    lookup_counter(map_fd, 1, &fexit_count) < 0) {
		perror("BPF_MAP_LOOKUP_ELEM");
		goto out;
	}
	if (!fentry_count || !fexit_count) {
		fprintf(stderr,
			"Native trampoline did not run both paths: fentry=%llu fexit=%llu\n",
			(unsigned long long)fentry_count,
			(unsigned long long)fexit_count);
		goto out;
	}
	printf("PASS: native fentry count=%llu, fexit count=%llu\n",
	       (unsigned long long)fentry_count,
	       (unsigned long long)fexit_count);
	result = 0;
out:
	if (fexit_link >= 0)
		close(fexit_link);
	if (fentry_link >= 0)
		close(fentry_link);
	if (fexit_prog >= 0)
		close(fexit_prog);
	if (fentry_prog >= 0)
		close(fentry_prog);
	if (map_fd >= 0)
		close(map_fd);
	return result;
}
