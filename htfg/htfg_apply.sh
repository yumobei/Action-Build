#!/usr/bin/env bash
# ============================================================================
# HTFG 注入脚本（在 Action-Build 的构建机上执行）
#
# 由 workflow 里 `HTFG Inject` 小步骤（标记块 HTFG-BOOTSTRAP）下载后运行；
# 该步骤只做：curl 本文件到 /tmp 再 `bash`——注入逻辑全部在本文件里，
# 这样上游 workflow 更新时我们只需要维护那两个小标记块。
#
# 为什么从 raw 地址下载内核文件，而不是从仓库 checkout 的文件取：
#   `Maximize Build Space` 步骤会把一块全新空卷挂载到 $GITHUB_WORKSPACE，
#   checkout 出来的文件（包括本脚本所在的 htg/ 目录）会被整个盖住。
#   URL 带 ?v=${GITHUB_SHA} 是为了绕开 raw CDN 的旧缓存（push 后立刻跑 CI 的场景）。
#
# 做七件事（与第 1 步的注入步骤等价 + 计数自检）：
#   1) 进入内核树并断言（kernel_workspace/kernel_platform/common，存在 kernel/sys.c）；
#   2) 下载 5 个内核侧文件（htfg.c / htfg.h / Kconfig / Makefile / patch_sysc.py）；
#   3) 放进 drivers/htfg/ 与 include/linux/；
#   4) 挂 drivers/Kconfig、drivers/Makefile、gki_defconfig（带守卫，防重复）；
#   5) 跑 patch_sysc.py 给 kernel/sys.c 装 prctl 钩子（锚点失配会非零退出）；
#   6) 过滤 IKCONFIG 假 config_data 的 root 相关行（只影响 /proc/config.gz）；
#   7) 计数自检：每处挂载/钩子必须恰好 1 次，否则 exit 1（构建红，绝不产出半套内核）。
# ============================================================================
set -euo pipefail

RAW="https://raw.githubusercontent.com/${GITHUB_REPOSITORY}/${GITHUB_REF_NAME}/htfg"
REV="${GITHUB_SHA:-}"

if [ -z "$REV" ]; then
    echo "❌ HTFG: 环境变量 GITHUB_SHA 未设置，无法固定下载版本"
    exit 1
fi

# ---- 0) 进入内核树（workflow 步骤的 CWD 是 $GITHUB_WORKSPACE 根目录）----
if [ -f kernel/sys.c ]; then
    :                                       # 已经在内核树里（手工单独运行时）
elif [ -f kernel_workspace/kernel_platform/common/kernel/sys.c ]; then
    cd kernel_workspace/kernel_platform/common
else
    echo "❌ HTFG: 找不到内核树（kernel/sys.c 不存在，当前目录 $(pwd)）"
    exit 1
fi
echo "HTFG inject: tree=$(pwd) rev=${REV:0:12}"

# ---- 1) 下载 5 个文件（?v= 固定到本次提交，防 CDN 旧缓存）----
SRC="/tmp/htfg-src"
rm -rf "$SRC"
mkdir -p "$SRC"
for f in htfg.c htfg.h Kconfig Makefile patch_sysc.py; do
    curl -fsSL --retry 3 "$RAW/$f?v=$REV" -o "$SRC/$f"
    if [ ! -s "$SRC/$f" ]; then
        echo "❌ HTFG: 下载失败或内容为空: $f"
        exit 1
    fi
done
ls -l "$SRC"

# ---- 2) 放入内核树 ----
mkdir -p drivers/htfg
cp -f "$SRC/htfg.c"   drivers/htfg/htfg.c
cp -f "$SRC/Kconfig"  drivers/htfg/Kconfig
cp -f "$SRC/Makefile" drivers/htfg/Makefile
cp -f "$SRC/htfg.h"   include/linux/htfg.h

# ---- 3) 挂进构建树（照抄本仓库 Apply RE_KERNEL 步骤的写法；带守卫，防重复执行）----
grep -q 'drivers/htfg/Kconfig' drivers/Kconfig || \
    sed -i '/endmenu/i source "drivers/htfg/Kconfig"' drivers/Kconfig
grep -qF 'obj-$(CONFIG_HTFG) += htfg/' drivers/Makefile || \
    sed -i '$a obj-$(CONFIG_HTFG) += htfg/' drivers/Makefile

# ---- 4) 打开配置（写进 gki_defconfig，后面 `make gki_defconfig` 会带上）----
grep -q '^CONFIG_HTFG=y' arch/arm64/configs/gki_defconfig || \
    echo 'CONFIG_HTFG=y' >> arch/arm64/configs/gki_defconfig

# ---- 5) 给 prctl 装钩子（锚点匹配不到会非零退出，让构建红掉）----
python3 "$SRC/patch_sysc.py" kernel/sys.c

# ---- 6) 过滤 IKCONFIG 假 config_data（只影响 /proc/config.gz）----
# 说明：真正编译用的 .config 不动；只让 kernel/config_data.gz（即 /proc/config.gz
# 和 Image 里的 IKCONFIG）少掉 KSU/SUSFS/HTFG/KPM 这些行，以及 BakaSU/simonpunk
# 的 Kconfig comment 行。精确锚定删除，不使用裸 KSU 关键字，避免误删
# CONFIG_NETFILTER_XT_TARGET_CHECKSUM 等含 "KSU" 的行。
install_fake_config_filter() {
    local kmake="kernel/Makefile"
    [ -f "$kmake" ] || { echo "HTFG fake config: missing $kmake"; exit 1; }

    python3 - "$kmake" <<'PY'
import io
import sys

path = sys.argv[1]
text = io.open(path, "r", encoding="utf-8", errors="surrogateescape", newline="").read()

# BakaSU 的 Kconfig 用 comment 把 BakaSU/simonpunk 警告块写进 .config；当前
# 实际出现 3 行名字 + 2 条分隔线。manual hook 变体的措辞不同，等切到该模式再补。
EXPRS = (" -e '/^CONFIG_KSU/d'"
         " -e '/^# CONFIG_KSU/d'"
         " -e '/^# KernelSU/d'"
         " -e '/^# end of KernelSU/d'"
         " -e '/^# Repo: .*susfs/d'"
         " -e '/^CONFIG_HTFG/d'"
         " -e '/^# CONFIG_HTFG/d'"
         " -e '/^CONFIG_KPM/d'"
         " -e '/^# CONFIG_KPM/d'"
         " -e '/^CONFIG_SUSFS/d'"
         " -e '/^# CONFIG_SUSFS/d'"
         " -e '/^# BakaSU/d'"
         " -e '/^# If anything mismatch with simonpunk/d'"
         " -e '/^# See simonpunk/d'"
         " -e '/^# ------------------------WARNING-------------------------------/d'"
         " -e '/^# --------------------------------------------------------------/d'")
MARKER = "# --- HTFG fake config filter ---"
UPSTREAM = "# --- fake_config injector ---"

def die(msg):
    sys.stderr.write("HTFG fake config: FAILED: %s\n" % msg)
    sys.exit(1)

lines = text.splitlines(keepends=True)

def find_line(pred, start=0):
    for i in range(start, len(lines)):
        if pred(lines[i]):
            return i
    return -1

def find_rule(start):
    ridx = find_line(lambda l: l.strip().startswith("$(obj)/config_data:"), start)
    if ridx < 0:
        return -1, -1
    for i in range(ridx + 1, min(ridx + 5, len(lines))):
        if "sed" in lines[i] and "$(KCONFIG_CONFIG) > $@" in lines[i]:
            return ridx, i
    return ridx, -1

up = find_line(lambda l: l.strip() == UPSTREAM)
if up >= 0:
    # The upstream fake_config rule is appended last and wins over the original
    # config_data rule.  Drop its ifneq/endif gate so the filter also applies in
    # the fallback build path (which does not pass CONFIG_FAKE_DISABLE).
    gstart = find_line(lambda l: l.strip() == "ifneq ($(strip $(CONFIG_FAKE_DISABLE)),)", up)
    gend = find_line(lambda l: l.strip() == "endif", gstart + 1) if gstart >= 0 else -1
    if gstart >= 0 or gend >= 0:
        if gstart < 0 or gend < 0:
            die("upstream fake_config gating is incomplete")
        ridx, sidx = find_rule(up)
        if ridx < 0 or sidx < 0 or not (gstart < ridx < gend):
            die("upstream fake_config gating does not wrap the config_data rule")
        del lines[gend]
        del lines[gstart]

    ridx, sidx = find_rule(up)
    if ridx < 0 or sidx < 0:
        die("upstream fake_config block has no expected config_data rule/sed line")

    if "CONFIG_KSU/d" not in lines[sidx]:
        if "CONFIG_KSU/d" in text:
            die("CONFIG_KSU/d exists outside the effective upstream rule")
        lines[sidx] = lines[sidx].replace(
            "$(KCONFIG_CONFIG) > $@", EXPRS + " $(KCONFIG_CONFIG) > $@", 1)

    if not any(MARKER in l for l in lines):
        lines.insert(up, MARKER + "\n")
else:
    if "CONFIG_KSU/d" in text:
        if MARKER in text:
            print("HTFG fake config: already patched")
            sys.exit(0)
        die("CONFIG_KSU/d exists but no upstream fake_config marker was found")
    ridx, _ = find_rule(0)
    if ridx < 0:
        die("cannot find $(obj)/config_data rule")

    if ridx + 1 < len(lines) and "$(call filechk,cat)" in lines[ridx + 1]:
        lines[ridx + 1] = ("\t$(Q)mkdir -p $(dir $@); sed" + EXPRS
                           + " $(KCONFIG_CONFIG) > $@\n")
        if not any(MARKER in l for l in lines):
            lines.insert(ridx, MARKER + "\n")
    else:
        fidx = find_line(lambda l: l.strip() == "filechk_cat = cat $<")
        if fidx < 0:
            die("cannot find config_data filechk recipe or filechk_cat")
        lines[fidx] = "filechk_cat = sed" + EXPRS + " $(KCONFIG_CONFIG)\n"
        if not any(MARKER in l for l in lines):
            lines.insert(fidx, MARKER + "\n")

out = "".join(lines)
n_filter_lines = sum(1 for l in lines if "CONFIG_KSU/d" in l)
if n_filter_lines != 1:
    die("expected exactly one CONFIG_KSU/d line, got %d" % n_filter_lines)
if out.count(MARKER) != 1:
    die("expected exactly one HTFG fake config marker, got %d"
        % out.count(MARKER))

io.open(path, "w", encoding="utf-8", errors="surrogateescape", newline="").write(out)
print("HTFG fake config: patched %s" % path)
PY
}
install_fake_config_filter

# ---- 7) 计数自检：任何一项不是恰好 1 次，立刻让构建失败 ----
FAIL=0
chk() {  # $1=描述 $2=期望值 $3=实际值
    if [ "$2" = "$3" ]; then
        echo "  ✅ $1 = $3"
    else
        echo "  ❌ $1 = $3（期望 $2）"
        FAIL=1
    fi
}
chk "kernel/sys.c 中 ksu_htfg_prctl 出现次数"          1 "$(grep -c  'ksu_htfg_prctl'                   kernel/sys.c || true)"
chk "drivers/Kconfig 中 HTFG 挂载行数"             1 "$(grep -c  'drivers/htfg/Kconfig'         drivers/Kconfig || true)"
chk "drivers/Makefile 中 HTFG 挂载行数"            1 "$(grep -cF 'obj-$(CONFIG_HTFG) += htfg/'  drivers/Makefile || true)"
chk "gki_defconfig 中 CONFIG_HTFG=y 行数"          1 "$(grep -c  '^CONFIG_HTFG=y'               arch/arm64/configs/gki_defconfig || true)"
chk "kernel/Makefile HTFG fake config marker"      1 "$(grep -c  'HTFG fake config filter'     kernel/Makefile || true)"
chk "kernel/Makefile CONFIG_KSU filter rule"       1 "$(grep -c  'CONFIG_KSU/d'                kernel/Makefile || true)"
if [ "$FAIL" != 0 ]; then
    echo "❌ HTFG 注入自检失败（详见上面计数）"
    exit 1
fi

ls -l drivers/htfg/ include/linux/htfg.h
echo "✅ HTFG 驱动已注入（rev ${REV:0:12}）"
