# KSU stat early-return experiment

Temporary experiment branch. Do not merge into `BakaSU` until the device
results are reviewed.

## What it changes

`ksu_stat_early_return.patch` modifies BakaSU's tracepoint `sys_enter`
handler only:

- for `newfstatat` / `faccessat` (and the arm64 compat equivalents), if the
  caller is not in the KSU allowlist, return without redirecting to the
  dispatcher;
- the two sucompat handlers already perform the same allowlist check and
  fall back to the original syscall for those callers, so behavior is
  unchanged;
- `execve`, `execveat` and `setresuid` are deliberately untouched: their
  handlers contain init/ksud/adb-root/sulog and uid-transition logic that
  must still run.

No new Kconfig symbol, device node, proc/sysfs entry, printk, module, or
exported symbol is added.

## How CI applies it

The workflow step `Apply KSU stat early-return patch (experiment)` runs after
BakaSU's `setup.sh`, downloads this patch from the current branch, and runs
`git apply --check` before applying it. A mismatch fails the build instead of
silently producing an unpatched kernel.

## Suggested build inputs

- Branch: `exp/ksu-stat-early-return`
- `KSU_META=main/main/Numbersf/7c383cf` (pin the BakaSU source the patch was
  generated against; adjust only if the patch is rebased)
- `SUSFS_META=-1`
- HTFG Inject / Verify blocks are included and must remain enabled.

## Validation

- Confirm the final config has `CONFIG_KSU_TRACEPOINT_HOOK=y` and no
  `CONFIG_KSU_SUSFS*`.
- Manager should still report `Tracepoint Syscall Redirect`.
- Native Detector cold starts: compare hit count with the current baseline.
- Chunqiu: note whether `Abnormal Environment` persists.
- Regression: boot, `su`, ksud, adb root, manager grant/revoke, module
  mounts, HTFG frame pull, touch op5/6, and a clean `dmesg`.
