#!/usr/bin/env bash
# ============================================================================
# HTFG 构建后校验（由 workflow 里 `HTFG Verify` 小步骤下载后运行）
#
# 位置：`- name: Make AnyKernel3` 之前——此时编译已经完成（无论 FAST 还是
#       Fallback 路径），能真正看到编译产物。第 1 步时这个校验被插在编译前，
#       从未生效，本步一并修复。
#
# 判定分三级（宁可红，不可静默降级）：
#   0) 先校验 IKCONFIG 假 config_data（FAST/fallback 都查；失败 exit 1）；
#   1) FAST 统一路径 kernel_workspace/kernel_platform/common/out/System.map
#      存在 → 严格：grep 符号 ksu_htfg_prctl，找不到 → exit 1；
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

# ---- 假 /proc/config.gz 检查（必须在 System.map 的 exit 0 之前）----
verify_fake_config() {
    local cfgz cfgd cfg tmp linecnt
    local bad_re
    bad_re='^(CONFIG_KSU|# CONFIG_KSU|# KernelSU|# end of KernelSU|# Repo: .*susfs|CONFIG_HTFG|# CONFIG_HTFG|CONFIG_KPM|# CONFIG_KPM|CONFIG_SUSFS|# CONFIG_SUSFS|# BakaSU|# If anything mismatch with simonpunk|# See simonpunk|# ------------------------WARNING-------------------------------|# --------------------------------------------------------------)'
    cfgz="kernel_workspace/kernel_platform/common/out/kernel/config_data.gz"
    [ -f "$cfgz" ] || cfgz="$(find_first -name config_data.gz)"
    cfgd=""
    [ -n "$cfgz" ] || cfgd="$(find_first -name config_data)"
    if [ -z "$cfgz" ] && [ -z "$cfgd" ]; then
        echo "ERROR: HTFG fake config: config_data.gz/config_data not found"
        exit 1
    fi

    tmp="$(mktemp)"
    if [ -n "$cfgz" ]; then
        if ! gzip -t "$cfgz" 2>/dev/null; then
            echo "ERROR: HTFG fake config: $cfgz is not valid gzip"
            rm -f "$tmp"
            exit 1
        fi
        gzip -dc "$cfgz" > "$tmp"
    else
        cat "$cfgd" > "$tmp"
    fi

    linecnt="$(wc -l < "$tmp")"
    if [ "$linecnt" -lt 100 ]; then
        echo "ERROR: HTFG fake config: only $linecnt lines (truncated/empty)"
        rm -f "$tmp"
        exit 1
    fi

    if grep -qE "$bad_re" "$tmp"; then
        echo "ERROR: HTFG fake config still contains root-related lines:"
        grep -nE "$bad_re" "$tmp" | sed -n '1,20p' || true
        rm -f "$tmp"
        exit 1
    fi

    if ! grep -qx 'CONFIG_IKCONFIG=y' "$tmp" || ! grep -qx 'CONFIG_IKCONFIG_PROC=y' "$tmp"; then
        echo "ERROR: HTFG fake config missing CONFIG_IKCONFIG=y / CONFIG_IKCONFIG_PROC=y"
        rm -f "$tmp"
        exit 1
    fi

    cfg="kernel_workspace/kernel_platform/common/out/.config"
    [ -f "$cfg" ] || cfg="$(find_first -name .config)"
    if [ -n "$cfg" ]; then
        if ! grep -q '^CONFIG_HTFG=y' "$cfg" || ! grep -q '^CONFIG_KSU=y' "$cfg"; then
            echo "ERROR: actual .config lost CONFIG_HTFG=y or CONFIG_KSU=y"
            rm -f "$tmp"
            exit 1
        fi
        if grep -q 'CONFIG_NETFILTER_XT_TARGET_CHECKSUM' "$cfg" && \
           ! grep -q 'CONFIG_NETFILTER_XT_TARGET_CHECKSUM' "$tmp"; then
            echo "ERROR: fake config over-deleted CHECKSUM (bare KSU pattern?)"
            rm -f "$tmp"
            exit 1
        fi
    else
        echo "::warning::HTFG fake config: actual .config not found; skip actual-config checks"
    fi

    rm -f "$tmp"
    echo "OK: HTFG fake config is clean; actual .config keeps HTFG/KSU"
}
verify_fake_config

# ---- 级 1：FAST 统一路径 ----
SMAP="kernel_workspace/kernel_platform/common/out/System.map"
if [ ! -f "$SMAP" ]; then
    # ---- 级 2：find 兜底 ----
    SMAP="$(find_first -name System.map)"
fi

if [ -n "$SMAP" ] && [ -f "$SMAP" ]; then
    echo "System.map: $SMAP"
    if grep -qE '[[:space:]]ksu_htfg_prctl$' "$SMAP"; then
        echo "✅ System.map 里找到 ksu_htfg_prctl"
        exit 0
    fi
    echo "❌ System.map 里没有 ksu_htfg_prctl —— 代码没有真正编进 Image"
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
