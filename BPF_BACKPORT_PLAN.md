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
- GitHub Actions runs #13 and #14 passed. Run #14 compiled the `Image.gz-dtb` target and reported all eight required BPF config symbols enabled. This proves the selected configuration compiles, not that the added BPF features work at runtime. Run #14 job: https://github.com/r1devlel/dreamworld_xiaomi_sdm845_experiment/actions/runs/38394474666/job/115286075365
- The target `kernel/bpf/Makefile` already builds the core verifier, maps, BTF, ring buffer, local storage, and XDP support; these are not new missing files to copy blindly.
- Compared with the 5.15 reference Makefile, the target does not build `trampoline.o`, `dispatcher.o`, or BPF iterator objects. The reference also has newer iterator, LSM, and struct_ops-related files. These are feature gaps, not automatically safe additions: they depend on newer BPF program/link types, verifier interfaces, RCU/task lifetime rules, and kernel APIs.
- The target `include/linux/bpf.h`, `include/uapi/linux/bpf.h`, and `kernel/bpf/verifier.c` are substantially older/smaller than the reference (about 1,016 vs 2,037 header lines, 2,284 vs 4,881 UAPI lines, and 10,161 vs 12,803 verifier lines). Do not replace them wholesale.
- ARM64 JIT source audit: target and donor `arch/arm64/net/bpf_jit_comp.c` are both around 1,000 lines and share the same core register mapping and emission architecture, but have non-identical lifecycle/helper code. The target has `arch_bpf_jit_check_func()` and a different JIT symbol-registration layout; donor has `bpf_jit_free_exec()` and newer core-side symbol/JIT-poke plumbing. Do not replace the JIT file wholesale; trace each changed helper against `kernel/bpf/core.c`, executable-memory allocation/freeing, kallsym registration, and the target's 4.9 APIs before porting any JIT changes.
- CI run #14 job steps all succeeded, including `Configure for Xiaomi Mi 8`, `Compile kernel and device trees`, `Diagnose BPF, RCU, and XDP build state`, and artifact upload. Artifact `dipper-kernel-bpf-port-14` exists (about 33 MB).
- `PAGE_POOL` is nested inside `if NET` and `page_pool.o` is conditionally built. Run #14's diagnostic reported `out/net/core/page_pool.o` missing, and `CONFIG_PAGE_POOL=y` was absent from `arch/arm64/configs/droidspaces.config`. Stage 2 therefore explicitly enables the symbol and makes CI assert both the final config and object file. Runtime DMA ownership/recycling still needs device-level validation.
- Next implementation decision: define the concrete feature set to backport (for example, XDP/page_pool stability vs. newer BPF trampoline/struct_ops/iterators) and map each requested feature to its complete dependency chain before touching kernel source.

## Current status
- Working branch created from lineage-23.2.
- Added donor-derived `include/net/page_pool.h` and `net/core/page_pool.c`.
- Wired `CONFIG_PAGE_POOL` and `page_pool.o` into Kconfig/Makefile, and enabled `CONFIG_PAGE_POOL=y` in the Mi 8 defconfig.
- Updated `include/net/xdp.h` and `net/core/xdp.c` with allocator tracking and XDP frame return APIs.
- Adapted the DMA-address accessor to Linux 4.9's `page_private()` storage because this target's `struct page` has no `dma_addr` member.
- Updated the manual GitHub Actions workflow to check out the selected ref (`github.ref`) so a run can build this branch.
- CI compile validation has succeeded in runs #13 and #14. Next step is runtime/semantic validation and feature-scoped dependency mapping, not treating a successful build as proof of complete eBPF support.


### Stage 2.1: enforce page-pool build coverage
- Added `CONFIG_PAGE_POOL=y` to the merged DroidSpaces config because the prior CI diagnostic showed the object was not built.
- Added a hard CI check for `CONFIG_PAGE_POOL=y` and `out/net/core/page_pool.o`, so a green kernel build cannot silently omit the allocator foundation.
- This remains compile-time validation only; hardware DMA/recycle semantics require runtime/device testing.

### Stage 2.2: hash-table allocation arithmetic audit
- CI run #19 passed on commit `79f2e632d0259a0c9c3e1ac6fbaca79b44dd9020`; all compile and artifact-upload steps succeeded: https://github.com/r1devlel/dreamworld_xiaomi_sdm845_experiment/actions/runs/38407207915
- The commit widens hash-element pointer-offset multiplication and preallocated element-buffer size multiplication to `u64`, avoiding intermediate 32-bit overflow.
- Reviewed the hash-map allocation path in `kernel/bpf/hashtab.c`: it already bounds key/value sizes, rejects zero/overflowed bucket counts, computes map memory cost in `u64`, and rejects costs that exceed the map-page accounting limit. No additional arithmetic change was made without a demonstrated failing case.
- Rechecked the staged `page_pool_unmap_page()` implementation against the donor implementation of `__page_pool_clean_page()`: it uses the existing DMA-unmap/clear-private helper, matching the intended release semantics. This compile check does not validate DMA ownership or XDP recycling on actual hardware.
- Run #19 artifact: `dipper-kernel-bpf-port-19`, about 31.4 MiB, expires 2026-10-20.
- Next step remains feature-scoped compatibility work: choose a concrete desired feature (such as BPF trampoline/struct_ops or iterator support), map its complete 4.9 dependency chain, and add runtime tests where hardware/userspace support permits. Do not copy the donor's 5.15 BPF core wholesale.

### Stage 2.3: aligned hash-element size validation
- CI run #21 passed on commit `b4187b1a43a66444d408fa6920db08cda55919af`: https://github.com/r1devlel/dreamworld_xiaomi_sdm845_experiment/actions/runs/38453460000
- Artifact `dipper-kernel-bpf-port-21` was uploaded successfully (32,965,554 bytes; expires 2026-10-20).
- Reviewed the latest hash-table allocation checks after the combined key/value-size guard landed. The element layout rounds both key and value storage to 8-byte boundaries, while the guard compared their unrounded sizes.
- Follow-up commit `dfd8fadc38abcf9776d8dd5f57dadc4d5472443f` changes the guard to calculate the aligned sizes in `u64` before comparing against `KMALLOC_MAX_SIZE`. This closes the small boundary gap without changing normal map layouts.
- CI for this follow-up is pending; do not treat the previous green run as validation of this new change. Runtime map-create/update tests are still needed, and the original `lineage-23.2` branch remains out of scope.

