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
# 做六件事（与第 1 步的注入步骤等价 + 计数自检）：
#   1) 进入内核树并断言（kernel_workspace/kernel_platform/common，存在 kernel/sys.c）；
#   2) 下载 5 个内核侧文件（htfg.c / htfg.h / Kconfig / Makefile / patch_sysc.py）；
#   3) 放进 drivers/htfg/ 与 include/linux/；
#   4) 挂 drivers/Kconfig、drivers/Makefile、gki_defconfig（带守卫，防重复）；
#   5) 跑 patch_sysc.py 给 kernel/sys.c 装 prctl 钩子（锚点失配会非零退出）；
#   6) 计数自检：每处挂载/钩子必须恰好 1 次，否则 exit 1（构建红，绝不产出半套内核）。
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

# ---- 6) 计数自检：任何一项不是恰好 1 次，立刻让构建失败 ----
FAIL=0
chk() {  # $1=描述 $2=期望值 $3=实际值
    if [ "$2" = "$3" ]; then
        echo "  ✅ $1 = $3"
    else
        echo "  ❌ $1 = $3（期望 $2）"
        FAIL=1
    fi
}
chk "kernel/sys.c 中 htfg_prctl 出现次数"          1 "$(grep -c  'htfg_prctl'                   kernel/sys.c || true)"
chk "drivers/Kconfig 中 HTFG 挂载行数"             1 "$(grep -c  'drivers/htfg/Kconfig'         drivers/Kconfig || true)"
chk "drivers/Makefile 中 HTFG 挂载行数"            1 "$(grep -cF 'obj-$(CONFIG_HTFG) += htfg/'  drivers/Makefile || true)"
chk "gki_defconfig 中 CONFIG_HTFG=y 行数"          1 "$(grep -c  '^CONFIG_HTFG=y'               arch/arm64/configs/gki_defconfig || true)"
if [ "$FAIL" != 0 ]; then
    echo "❌ HTFG 注入自检失败（详见上面计数）"
    exit 1
fi

ls -l drivers/htfg/ include/linux/htfg.h
echo "✅ HTFG 驱动已注入（rev ${REV:0:12}）"
