#!/usr/bin/env bash
# ============================================================================
# HTFG 构建后校验（由 workflow 里 `HTFG Verify` 小步骤下载后运行）
#
# 位置：`- name: Make AnyKernel3` 之前——此时编译已经完成（无论 FAST 还是
#       Fallback 路径），能真正看到编译产物。第 1 步时这个校验被插在编译前，
#       从未生效，本步一并修复。
#
# 判定分三级（宁可红，不可静默降级）：
#   1) FAST 统一路径 kernel_workspace/kernel_platform/common/out/System.map
#      存在 → 严格：grep 符号 htfg_prctl，找不到 → exit 1；
#   2) 上述文件不在 → find 兜底（排除 prebuilts/），找到同样严格判定；
#   3) 都没有（回退/bazel 构建路径）→ 打印 ::warning::，改用旁证：
#      .config 里有 CONFIG_HTFG=y 且 drivers/htfg/htfg.o 已产出 → 通过；
#      旁证也不足 → exit 1，绝不绿灯放行。
# ============================================================================
set -euo pipefail

find_first() {  # $1 = find 表达式（-name / -path 之后的部分）
    find kernel_workspace/kernel_platform -maxdepth 8 "$@" 2>/dev/null \
        | grep -v '/prebuilts/' | head -n 1 || true
}

# ---- 级 1：FAST 统一路径 ----
SMAP="kernel_workspace/kernel_platform/common/out/System.map"
if [ ! -f "$SMAP" ]; then
    # ---- 级 2：find 兜底 ----
    SMAP="$(find_first -name System.map)"
fi

if [ -n "$SMAP" ] && [ -f "$SMAP" ]; then
    echo "System.map: $SMAP"
    if grep -qE '[[:space:]]htfg_prctl$' "$SMAP"; then
        echo "✅ System.map 里找到 htfg_prctl"
        exit 0
    fi
    echo "❌ System.map 里没有 htfg_prctl —— 代码没有真正编进 Image"
    echo "---- System.map 里含 htfg 的行（供排查）----"
    grep -i 'htfg' "$SMAP" | head -n 20 || echo "  （一行都没有）"
    exit 1
fi

# ---- 级 3：无 System.map 的回退/bazel 路径 → 旁证 ----
echo "::warning::HTFG: 没找到 System.map（回退/bazel 构建路径），降级用旁证判定"
CFG="kernel_workspace/kernel_platform/common/out/.config"
if [ ! -f "$CFG" ]; then
    CFG="$(find kernel_workspace/kernel_platform/out \
              kernel_workspace/kernel_platform/common/out \
              -maxdepth 5 -name .config 2>/dev/null | head -n 1 || true)"
fi
[ -f "$CFG" ] || CFG="$(find_first -name .config)"
OBJ="kernel_workspace/kernel_platform/common/out/drivers/htfg/htfg.o"
[ -f "$OBJ" ] || OBJ="$(find_first -path '*/drivers/htfg/htfg.o')"

echo "  旁证 .config : ${CFG:-（未找到）}"
echo "  旁证 htfg.o  : ${OBJ:-（未找到）}"
if [ -n "$CFG" ] && grep -q '^CONFIG_HTFG=y' "$CFG" && [ -n "$OBJ" ]; then
    echo "✅ HTFG 旁证通过：CONFIG_HTFG=y 且 drivers/htfg/htfg.o 已产出"
    exit 0
fi
echo "❌ HTFG 旁证不足：既没有 System.map，也未能确认 CONFIG_HTFG=y + htfg.o"
exit 1
