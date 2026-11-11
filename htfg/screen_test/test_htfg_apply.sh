#!/usr/bin/env bash
# ============================================================================
# HTFG_Kernel_Original_Screenshot Stage 2A test-driver injection.
#
# TEST-ONLY. This script is downloaded and executed by the temporary test
# branch's htg/htfg_apply.sh (official script + appended block).  It is NOT
# part of the official root scheme and is never referenced by the official
# BakaSU branch.
#
# What it does (after the official HTFG injection has already run):
#   1) locate the kernel tree (same logic as htg/htfg_apply.sh);
#   2) download the four test-driver files from htg/screen_test/, with the raw
#      URL pinned to the commit SHA (the branch form can hit a stale CDN cache);
#   3) copy them to drivers/htfg_screen_test/;
#   4) hook drivers/Kconfig, drivers/Makefile and gki_defconfig;
#   5) count self-check: every hook must appear exactly once, otherwise the
#      build goes red (never a half-injected kernel).
#
# All console messages are ASCII/English.
# ============================================================================
set -euo pipefail

if [ -z "${GITHUB_SHA:-}" ]; then
    echo "ERROR: HTFG screen-test: GITHUB_SHA is not set"
    exit 1
fi

# Pin raw URLs to the commit SHA, not the branch name: the branch form can be
# served from a stale CDN cache (including a cached 404 from before the push).
RAW="https://raw.githubusercontent.com/${GITHUB_REPOSITORY}/${GITHUB_SHA}/htfg/screen_test"
REV="${GITHUB_SHA}"

# ---- 0) enter the kernel tree (workflow step cwd is $GITHUB_WORKSPACE) ----
if [ -f kernel/sys.c ]; then
    :
elif [ -f kernel_workspace/kernel_platform/common/kernel/sys.c ]; then
    cd kernel_workspace/kernel_platform/common
else
    echo "ERROR: HTFG screen-test: kernel tree not found (cwd $(pwd))"
    exit 1
fi
echo "HTFG screen-test: tree=$(pwd) rev=${REV:0:12}"

# ---- 1) download the test driver files ----
SRC="/tmp/htfg-screen-test-src"
rm -rf "$SRC"
mkdir -p "$SRC"

fetch_file() {  # $1 = file name, $2 = output path
    if curl -fsSL --retry 5 --retry-all-errors --retry-delay 3 \
            "$RAW/$1" -o "$2"; then
        return 0
    fi
    # Fallback host: GitHub API (different cache path), raw media type.
    echo "WARN: raw download failed for $1, trying GitHub API"
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 3 \
        -H 'Accept: application/vnd.github.raw' \
        "https://api.github.com/repos/${GITHUB_REPOSITORY}/contents/htfg/screen_test/$1?ref=${REV}" \
        -o "$2"
}

for f in htg_screen_test.c htg_screen_test.h Kconfig Makefile; do
    if ! fetch_file "$f" "$SRC/$f" || [ ! -s "$SRC/$f" ]; then
        echo "ERROR: HTFG screen-test: download failed or empty: $f"
        echo "       url: $RAW/$f"
        exit 1
    fi
done
ls -l "$SRC"

# ---- 2) install into the kernel tree ----
mkdir -p drivers/htfg_screen_test
cp -f "$SRC/htg_screen_test.c" "$SRC/htg_screen_test.h" \
      "$SRC/Kconfig" "$SRC/Makefile" drivers/htfg_screen_test/

# ---- 3) hook Kconfig / Makefile / defconfig (guarded, idempotent) ----
grep -q 'drivers/htfg_screen_test/Kconfig' drivers/Kconfig || \
    sed -i '/endmenu/i source "drivers/htfg_screen_test/Kconfig"' drivers/Kconfig

grep -qF 'obj-$(CONFIG_HTFG_SCREEN_TEST) += htg_screen_test/' drivers/Makefile || \
    sed -i '$a obj-$(CONFIG_HTFG_SCREEN_TEST) += htg_screen_test/' drivers/Makefile

grep -q '^CONFIG_HTFG_SCREEN_TEST=y' arch/arm64/configs/gki_defconfig || \
    echo 'CONFIG_HTFG_SCREEN_TEST=y' >> arch/arm64/configs/gki_defconfig

# ---- 4) count self-check ----
FAIL=0
chk() {  # $1=description $2=expected $3=actual
    if [ "$2" = "$3" ]; then
        echo "  OK   $1 = $3"
    else
        echo "  FAIL $1 = $3 (expected $2)"
        FAIL=1
    fi
}
chk "drivers/Kconfig screen-test hook" 1 \
    "$(grep -c 'drivers/htfg_screen_test/Kconfig' drivers/Kconfig || true)"
chk "drivers/Makefile screen-test hook" 1 \
    "$(grep -cF 'obj-$(CONFIG_HTFG_SCREEN_TEST) += htg_screen_test/' drivers/Makefile || true)"
chk "gki_defconfig CONFIG_HTFG_SCREEN_TEST=y" 1 \
    "$(grep -c '^CONFIG_HTFG_SCREEN_TEST=y' arch/arm64/configs/gki_defconfig || true)"
chk "test driver source files" 4 \
    "$(ls -1 drivers/htfg_screen_test/htg_screen_test.c \
              drivers/htfg_screen_test/htg_screen_test.h \
              drivers/htfg_screen_test/Kconfig \
              drivers/htfg_screen_test/Makefile 2>/dev/null | wc -l)"

if [ "$FAIL" != 0 ]; then
    echo "ERROR: HTFG screen-test: injection self-check failed"
    exit 1
fi

ls -l drivers/htfg_screen_test/
echo "OK: HTFG screen-test driver injected (rev ${REV:0:12})"
