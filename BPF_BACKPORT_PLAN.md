# BPF Backport Plan: Mido reference -> Dreamworld dipper

## Target
- Repository: r1devlel/dreamworld_xiaomi_sdm845_experiment
- Base branch: lineage-23.2
- Working branch: bpf-port-mido-stage1
- Target device: Xiaomi Mi 8 (dipper)
- Kernel baseline: Linux 4.9.337
- Reference repository: r1devlel/psionic_kernel_xiaomi_mido
- Reference branch: 5.15-bpf (the checked-out Makefile also reports Linux 4.9.337)

## Rules
1. Keep the original target branch unchanged.
2. Port dependency groups, not isolated files copied blindly.
3. Preserve useful upstream commit messages and provenance where practical.
4. Build and inspect the first real compiler/linker error after each stage.
5. Do not replace task-RCU or networking lifetime semantics with superficial stubs just to make linking pass.

## Initial audit
- Target config already enables CONFIG_BPF_SYSCALL and CONFIG_CGROUP_BPF.
- Target include/net/xdp.h is older/simpler than the reference and lacks xdp_mem_info/page-pool integration.
- Target has no include/net/page_pool.h or net/core/page_pool.c at the inspected base.
- Target net/core/Makefile builds xdp.o but not page_pool.o.
- Prior CI failure showed missing net/page_pool.h, TCP congestion-control API differences, and unresolved XDP/BPF symbols.

## Stages
### Stage 0: baseline and dependency inventory
- Confirm target build workflow and defconfig.
- Map reference commits touching XDP, page_pool, BPF core, TCP struct_ops, and task-RCU.
- Record symbol providers and required config options before moving code.

### Stage 1: XDP/page_pool foundation
- Port page_pool API/implementation and required Kconfig/Makefile wiring as a coherent group.
- Port the matching xdp_mem_info and XDP frame return/recycle dependencies.
- Check DMA mapping, page ownership, NAPI context, and config guards carefully.

### Stage 2: BPF/XDP build integration
- Add only the BPF/XDP objects required by the selected feature set.
- Verify every unresolved symbol has a real implementation and compatible declaration.

### Stage 3: Linux 4.9 compatibility
- Adapt TCP congestion-control struct_ops and socket/BPF APIs to the target 4.9 interfaces.
- Avoid dummy fields/functions unless their semantics are proven safe.

### Stage 4: CI validation
- Run the dipper GitHub Actions build.
- Fix the earliest causal error first; warnings such as objdump's unrecognized-form warning are not assumed to be fatal without evidence.
- Keep each stage reviewable and revertible.

## Stage 2 audit (2026-10-13)
- Latest GitHub Actions run #13 passed: `Image.gz-dtb` exists and the eight required BPF config symbols are enabled. This proves the selected configuration compiles, not that the added BPF features work at runtime.
- The target `kernel/bpf/Makefile` already builds the core verifier, maps, BTF, ring buffer, local storage, and XDP support; these are not new missing files to copy blindly.
- Compared with the 5.15 reference Makefile, the target does not build `trampoline.o`, `dispatcher.o`, or BPF iterator objects. The reference also has newer iterator, LSM, and struct_ops-related files. These are feature gaps, not automatically safe additions: they depend on newer BPF program/link types, verifier interfaces, RCU/task lifetime rules, and kernel APIs.
- The target `include/linux/bpf.h` and `kernel/bpf/verifier.c` are substantially older/smaller than the reference (about 1,016 vs 2,037 header lines and 10,161 vs 12,803 verifier lines). Do not replace them wholesale.
- `PAGE_POOL` is nested inside `if NET`; `page_pool.o` is conditionally built and enabled in the dipper defconfig. The XDP/page-pool stage compiles, but runtime DMA ownership/recycling still needs device-level validation.
- Next implementation decision: define the concrete feature set to backport (for example, XDP/page_pool stability vs. newer BPF trampoline/struct_ops/iterators) and map each requested feature to its complete dependency chain before touching kernel source.

## Current status
- Working branch created from lineage-23.2.
- Added donor-derived `include/net/page_pool.h` and `net/core/page_pool.c`.
- Wired `CONFIG_PAGE_POOL` and `page_pool.o` into Kconfig/Makefile, and enabled `CONFIG_PAGE_POOL=y` in the Mi 8 defconfig.
- Updated `include/net/xdp.h` and `net/core/xdp.c` with allocator tracking and XDP frame return APIs.
- Adapted the DMA-address accessor to Linux 4.9's `page_private()` storage because this target's `struct page` has no `dma_addr` member.
- Updated the manual GitHub Actions workflow to check out the selected ref (`github.ref`) so a run can build this branch.
- CI has not yet been run; next step is compile validation and fixing the earliest causal error.
