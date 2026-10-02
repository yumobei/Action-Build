#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
给 kernel/sys.c 装上 HTFG 的 prctl 钩子。

用法：
    python3 patch_sysc.py <内核树>/kernel/sys.c

做两件事（幂等，重复执行不会重复插入）：
  1. 在第一个 `#include <linux/...>` 之后插入 `#include <linux/htfg.h>`；
  2. 在 prctl 函数体里、所有局部变量声明之后、LSM 钩子之前插入：

        if (unlikely(option == HTFG_PRCTL_MAGIC))
            return htfg_prctl(arg2, arg3, arg4, arg5);

插在 LSM 钩子之前有两个好处：不与 SELinux 产生任何交互；且此时前面全是声明，
不会触发 -Wdeclaration-after-statement。

找不到锚点时**以非零码退出**并把 prctl 函数开头打印出来——宁可让构建失败，
也不能静默产出一个没有钩子的内核。
"""

import io
import sys

INCLUDE_LINE = "#include <linux/htfg.h>\n"

HOOK = (
    "\tif (unlikely(option == HTFG_PRCTL_MAGIC))\n"
    "\t\treturn htfg_prctl(arg2, arg3, arg4, arg5);\n"
    "\n"
)

# 优先级：(锚点, 插在锚点之前还是之后)
ANCHORS = [
    ("\terror = security_task_prctl(option, arg2, arg3, arg4, arg5);\n", "before"),
    ("\tstruct task_struct *me = current;\n", "after"),
]

PRCTL_START = "SYSCALL_DEFINE5(prctl,"


def die(msg, lines=None, start=None):
    sys.stderr.write("patch_sysc: FAILED: %s\n" % msg)
    if lines is not None and start is not None and start >= 0:
        end = min(len(lines), start + 30)
        sys.stderr.write("---- first %d lines of prctl() in kernel/sys.c ----\n" % (end - start))
        sys.stderr.writelines(lines[start:end])
        sys.stderr.write("--------------------------------------------------\n")
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: patch_sysc.py <path/to/kernel/sys.c>\n")
        sys.exit(2)

    path = sys.argv[1]
    with io.open(path, "r", encoding="utf-8", errors="surrogateescape", newline="") as f:
        text = f.read()

    if "htfg_prctl" in text:
        print("patch_sysc: already patched, skipping -> %s" % path)
        return

    lines = text.splitlines(keepends=True)
    if not lines:
        die("file is empty")

    # ---- 定位 prctl 函数体（后面所有查找都限定在它之后）----
    pidx = -1
    for i, ln in enumerate(lines):
        if ln.startswith(PRCTL_START):
            pidx = i
            break
    if pidx < 0:
        die("cannot find %r (kernel version difference?)" % PRCTL_START, lines, 0)

    # ---- 定位 include 插入点 ----
    inc_idx = -1
    for i, ln in enumerate(lines):
        if ln.startswith("#include <linux/"):
            inc_idx = i
            break
    if inc_idx < 0:
        die("no `#include <linux/...>` line found, cannot insert header", lines, pidx)

    # ---- 定位钩子插入点 ----
    # 先把两个插入点都找齐再动文件：任何一步失败都不会留下半成品（构建会红掉，
    # 而不是刷进一个"改了一半"的内核）
    hit = None
    for anchor, where in ANCHORS:
        try:
            idx = lines.index(anchor, pidx)
        except ValueError:
            continue
        hit = (idx, where)
        break

    if hit is None:
        die(
            "none of the anchors matched: %s" % " / ".join(repr(a[0]) for a in ANCHORS),
            lines,
            pidx,
        )

    idx, where = hit

    # ---- 开始插入 ----
    if "#include <linux/htfg.h>" not in text:
        lines.insert(inc_idx + 1, INCLUDE_LINE)
        if idx > inc_idx:       # include 插在钩子之前，行号要顺移
            idx += 1

    if where == "before":
        lines.insert(idx, HOOK)
    else:
        lines.insert(idx + 1, HOOK)

    out = "".join(lines)

    # ---- 自检 ----
    for must in ("#include <linux/htfg.h>", "HTFG_PRCTL_MAGIC", "htfg_prctl"):
        if must not in out:
            die("self-check failed: %r missing from result" % must, lines, pidx)

    with io.open(path, "w", encoding="utf-8", errors="surrogateescape", newline="") as f:
        f.write(out)

    print("patch_sysc: prctl hook installed into %s" % path)


if __name__ == "__main__":
    main()
