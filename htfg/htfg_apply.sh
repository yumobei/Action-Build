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

# ============================================================================
# Stage 2A test driver injection (TEMPORARY TEST BRANCH ONLY).
#
# The four driver files are EMBEDDED below on purpose: CI makes no additional
# raw.githubusercontent.com request for them.  The official HTFG injection
# above is unchanged.
# ============================================================================
SRC=/tmp/htfg-screen-test-src
rm -rf "$SRC"
mkdir -p "$SRC"
cat > "$SRC/htfg_screen_test.c" <<'__HTFG_EOF_C__'
// SPDX-License-Identifier: GPL-2.0
/*
 * HTFG_Kernel_Original_Screenshot Stage 2A test driver.
 *
 * TEST-ONLY. Built into a temporary root Action-Build test kernel; not part
 * of HTFG and not part of HTFG_Kernel_Original.
 *
 * Goal: prove that one full-screen RGB888 frame from the main display can be
 * captured through the vendor mediatek-drm CWB/WDMA path into a kernel buffer
 * and handed to userspace through a root-only debugfs file.
 *
 * Mechanism (details and evidence in docs/Stage2_设计.md):
 *   - mediatek-drm.ko is a vendor module; its CWB helpers are not exported.
 *     Resolve drm_dev / mtk_drm_cwb_enable / mtk_drm_gem_create /
 *     mtk_drm_framebuffer_create with kallsyms_lookup_name().
 *   - cwb_info lives at crtc + 0x1388 (confirmed by disassembling the
 *     device's mediatek-drm.ko).
 *   - First enable lets the vendor allocate cwb_info + two 128-wide stock
 *     buffers.  Replace them with two full-screen MTK GEM framebuffers, keep
 *     the old stock framebuffers alive, then enable CWB again and wait for
 *     copy_done.
 *   - The copy buffer is allocated once and never freed while the driver is
 *     alive, so an in-flight vendor memcpy can never hit freed memory.
 *   - No printk.  No new device node.  No procfs/sysfs entries.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/vmalloc.h>
#include <linux/kallsyms.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/jiffies.h>
#include <linux/overflow.h>
#include <linux/limits.h>
#include <linux/build_bug.h>
#include <linux/stddef.h>
#include <asm/barrier.h>
#include <drm/drm_crtc.h>
#include <drm/drm_gem.h>
#include <drm/drm_framebuffer.h>
#include <drm/drm_fourcc.h>

#include "htfg_screen_test.h"

/*
 * Compile-time layout guard: the vendor module kzallocs 0xB0 bytes for
 * cwb_info and stores funcs at 0xA8 / type at 0xA0 (seen in the
 * mtk_drm_cwb_enable disassembly).  If this ever stops matching, build fails
 * instead of corrupting memory at runtime.
 */
static_assert(sizeof(struct mtk_cwb_info) == 0xB0,
	      "struct mtk_cwb_info layout differs from the vendor module");
static_assert(offsetof(struct mtk_cwb_info, buffer) == 0x20,
	      "struct mtk_cwb_info buffer offset mismatch");
static_assert(offsetof(struct mtk_cwb_info, type) == 0xA0,
	      "struct mtk_cwb_info type offset mismatch");
static_assert(offsetof(struct mtk_cwb_info, funcs) == 0xA8,
	      "struct mtk_cwb_info funcs offset mismatch");

#define HTG_PPM_TIMEOUT_MS	5000
#define HTG_DISABLE_GRACE_MS	100
#define HTG_WARMUP_MS		200
#define HTG_CMD_MAX		16

typedef bool (*htg_cwb_enable_fn)(int en,
				  const struct mtk_cwb_funcs *funcs,
				  enum CWB_BUFFER_TYPE type);
typedef struct mtk_drm_gem_obj *(*htg_gem_create_fn)(struct drm_device *dev,
						     size_t size,
						     bool alloc_kmap);
typedef struct drm_framebuffer *(*htg_fb_create_fn)(struct drm_device *dev,
						    const struct drm_mode_fb_cmd2 *mode,
						    struct drm_gem_object *obj);

struct htg_screen {
	struct mutex lock;
	bool symbols_ok;
	htg_cwb_enable_fn cwb_enable;
	htg_gem_create_fn gem_create;
	htg_fb_create_fn fb_create;
	struct drm_driver *mtk_driver;
	struct drm_device *dev;
	struct drm_crtc *crtc;
	struct mtk_cwb_info *cwb_info;
	/* Stock 128-wide framebuffers; kept alive on purpose (never freed here). */
	struct drm_framebuffer *old_fb[2];
	/* Our full-screen framebuffers. */
	struct drm_framebuffer *full_fb[2];
	void *full_kvaddr[2];
	dma_addr_t full_dma[2];
	/* PPM copy of the last frame; allocated once, never freed while alive. */
	void *ppm;
	size_t ppm_len;
	unsigned int width;
	unsigned int height;
	bool frame_valid;
	bool waiting;
};

static struct htg_screen htg;
static struct completion htg_copy_done;
static struct dentry *htg_dentry;

/*
 * DRM_FORMAT_RGB888 stores 24-bit little-endian R:G:B, so the vendor CWB
 * writes B,G,R in memory while PPM expects R,G,B.  Swap in place once, in
 * the completion callback, before userspace can read the frame; readers
 * then get byte-exact data with any read size.  A later capture overwrites
 * the buffer with fresh vendor bytes before the next swap.
 */
static void htg_swap_rb(u8 *buf, size_t len)
{
	size_t i;
	u8 t;

	for (i = 0; i + 2 < len; i += 3) {
		t = buf[i];
		buf[i] = buf[i + 2];
		buf[i + 2] = t;
	}
}

/*
 * Called by the vendor monitor thread after mtk_drm_cwb_copy_buf() finished.
 * Do NOT annotate with __nocfi: this function is the callee of a CFI-checked
 * indirect call from mediatek-drm.ko and must carry the canonical type
 * "void (void *, enum CWB_BUFFER_TYPE)".
 */
static void htg_screen_copy_done(void *buffer, enum CWB_BUFFER_TYPE type)
{
	if (!READ_ONCE(htg.waiting))
		return;
	if (buffer != READ_ONCE(htg.ppm))
		return;
	htg_swap_rb(htg.ppm, htg.ppm_len);
	WRITE_ONCE(htg.waiting, false);
	complete(&htg_copy_done);
}

static const struct mtk_cwb_funcs htg_cwb_funcs = {
	.get_buffer = NULL,
	.copy_done = htg_screen_copy_done,
};

/*
 * __nocfi: the callee lives in the vendor module, outside the built-in CFI
 * type space.  These wrappers are the only places that call vendor function
 * pointers.
 */
static noinline __nocfi bool
htg_cwb_enable_call(htg_cwb_enable_fn fn, int en,
		    const struct mtk_cwb_funcs *funcs)
{
	return fn(en, funcs, IMAGE_ONLY);
}

static noinline __nocfi struct mtk_drm_gem_obj *
htg_gem_create_call(htg_gem_create_fn fn, struct drm_device *dev, size_t size)
{
	return fn(dev, size, true);
}

static noinline __nocfi struct drm_framebuffer *
htg_fb_create_call(htg_fb_create_fn fn, struct drm_device *dev,
		   const struct drm_mode_fb_cmd2 *mode,
		   struct drm_gem_object *obj)
{
	return fn(dev, mode, obj);
}

static int htg_resolve_symbols(struct htg_screen *s)
{
	struct drm_device *dev;
	unsigned long drm_dev_sym;
	unsigned long mtk_driver_sym;
	union {
		unsigned long addr;
		htg_cwb_enable_fn fn;
	} enable;
	union {
		unsigned long addr;
		htg_gem_create_fn fn;
	} gem;
	union {
		unsigned long addr;
		htg_fb_create_fn fn;
	} fb;

	if (s->symbols_ok)
		return 0;

	drm_dev_sym = kallsyms_lookup_name("drm_dev");
	if (!drm_dev_sym)
		return -ENODEV;
	dev = READ_ONCE(*(struct drm_device **)drm_dev_sym);
	if (IS_ERR_OR_NULL(dev))
		return -ENODEV;

	enable.addr = kallsyms_lookup_name("mtk_drm_cwb_enable");
	gem.addr = kallsyms_lookup_name("mtk_drm_gem_create");
	fb.addr = kallsyms_lookup_name("mtk_drm_framebuffer_create");
	mtk_driver_sym = kallsyms_lookup_name("mtk_drm_driver");
	if (!enable.addr || !gem.addr || !fb.addr || !mtk_driver_sym)
		return -ENODEV;

	/*
	 * Guard against a same-named drm_dev in another module: the device's
	 * drm_driver pointer must be mediatek-drm's own mtk_drm_driver.
	 */
	if (dev->driver != (struct drm_driver *)mtk_driver_sym)
		return -ENODEV;

	s->cwb_enable = enable.fn;
	s->gem_create = gem.fn;
	s->fb_create = fb.fn;
	s->mtk_driver = dev->driver;
	s->dev = dev;
	s->symbols_ok = true;
	return 0;
}

static int htg_pick_crtc(struct htg_screen *s)
{
	struct drm_device *dev = s->dev;

	if (list_empty(&dev->mode_config.crtc_list))
		return -ENODEV;
	s->crtc = list_first_entry(&dev->mode_config.crtc_list,
				   struct drm_crtc, head);
	if (IS_ERR_OR_NULL(s->crtc))
		return -ENODEV;
	return 0;
}

static int htg_crtc_mode(struct htg_screen *s, unsigned int *w, unsigned int *h)
{
	struct drm_crtc_state *state = READ_ONCE(s->crtc->state);

	if (!state || !state->active)
		return -ENODEV;
	if (!state->adjusted_mode.hdisplay || !state->adjusted_mode.vdisplay)
		return -ENODEV;
	*w = state->adjusted_mode.hdisplay;
	*h = state->adjusted_mode.vdisplay;
	return 0;
}

static struct mtk_cwb_info *htg_get_cwb_info(struct htg_screen *s)
{
	return READ_ONCE(*(struct mtk_cwb_info **)
			 ((char *)s->crtc + HTFG_CWB_INFO_OFFSET));
}

static void htg_free_full_buffers(struct htg_screen *s)
{
	int i;

	for (i = 0; i < 2; i++) {
		if (s->full_fb[i]) {
			drm_framebuffer_put(s->full_fb[i]);
			s->full_fb[i] = NULL;
		}
		s->full_kvaddr[i] = NULL;
		s->full_dma[i] = 0;
	}
}

static int htg_alloc_full_buffers(struct htg_screen *s, unsigned int w,
				  unsigned int h)
{
	struct drm_mode_fb_cmd2 mode = {0};
	struct mtk_drm_gem_obj *gem;
	struct drm_framebuffer *fb;
	size_t size;
	int i, ret = -ENOMEM;

	if (check_mul_overflow((size_t)w, (size_t)h, &size) ||
	    check_mul_overflow(size, (size_t)3, &size))
		return -EINVAL;

	mode.width = w;
	mode.height = h;
	mode.pixel_format = DRM_FORMAT_RGB888;
	mode.pitches[0] = w * 3;

	for (i = 0; i < 2; i++) {
		gem = htg_gem_create_call(s->gem_create, s->dev, size);
		if (IS_ERR_OR_NULL(gem)) {
			ret = gem ? PTR_ERR(gem) : -ENOMEM;
			goto fail;
		}
		/* Layout sanity: alloc_kmap=true must give kvaddr, DMA must exist. */
		if (!gem->kvaddr || !gem->dma_addr) {
			drm_gem_object_put(&gem->base);
			ret = -EINVAL;
			goto fail;
		}
		/*
		 * mtk_drm_framebuffer_create() takes over the GEM reference:
		 * its destroy callback drops it.  Do not put it here again.
		 */
		fb = htg_fb_create_call(s->fb_create, s->dev, &mode, &gem->base);
		if (IS_ERR_OR_NULL(fb)) {
			drm_gem_object_put(&gem->base);
			ret = fb ? PTR_ERR(fb) : -ENOMEM;
			goto fail;
		}
		s->full_fb[i] = fb;
		s->full_kvaddr[i] = gem->kvaddr;
		s->full_dma[i] = gem->dma_addr;
	}

	s->width = w;
	s->height = h;
	s->ppm_len = size;
	s->ppm = vmalloc(size);
	if (!s->ppm) {
		ret = -ENOMEM;
		goto fail;
	}
	return 0;

fail:
	htg_free_full_buffers(s);
	s->ppm_len = 0;
	return ret;
}

/*
 * Point cwb_info at our full-screen buffers.  The stock buffers are saved the
 * first time and deliberately not freed; an in-flight WDMA write may still be
 * targeting them.
 */
static void htg_point_buffers(struct htg_screen *s)
{
	struct mtk_cwb_info *info = s->cwb_info;
	int i;

	for (i = 0; i < 2; i++) {
		if (!s->old_fb[i] && info->buffer[i].fb != s->full_fb[i])
			s->old_fb[i] = info->buffer[i].fb;
		info->buffer[i].fb = s->full_fb[i];
		info->buffer[i].addr_mva = s->full_dma[i];
		info->buffer[i].addr_va = (u64)s->full_kvaddr[i];
		info->buffer[i].dst_roi.x = 0;
		info->buffer[i].dst_roi.y = 0;
		info->buffer[i].dst_roi.width = s->width;
		info->buffer[i].dst_roi.height = s->height;
		info->buffer[i].timestamp = 0;
	}
	info->copy_w = 0;
	info->copy_h = 0;
}

static int htg_prepare(struct htg_screen *s)
{
	struct mtk_cwb_info *info;
	unsigned int w, h;
	int ret;

	ret = htg_resolve_symbols(s);
	if (ret)
		return ret;

	if (!s->crtc) {
		ret = htg_pick_crtc(s);
		if (ret)
			return ret;
	}

	ret = htg_crtc_mode(s, &w, &h);
	if (ret)
		return ret;

	info = htg_get_cwb_info(s);
	if (!info || !info->buffer[0].fb) {
		/*
		 * First enable: let the vendor allocate cwb_info and the two
		 * 128-wide stock buffers.  mtk_drm_cwb_info_init() needs a valid
		 * crtc->state (checked above).
		 */
		if (!htg_cwb_enable_call(s->cwb_enable, 1, NULL))
			return -ENODEV;

		info = htg_get_cwb_info(s);
		if (!info) {
			htg_cwb_enable_call(s->cwb_enable, 0, NULL);
			return -ENODEV;
		}
		if (!info->enable || !info->comp ||
		    !info->buffer[0].dst_roi.width ||
		    info->buffer[0].dst_roi.width > 128 ||
		    !info->buffer[0].dst_roi.height ||
		    !info->buffer[0].fb || !info->buffer[0].addr_va ||
		    !info->buffer[0].addr_mva) {
			/* Wrong cwb_info offset / not CRTC0 / stock init failed. */
			htg_cwb_enable_call(s->cwb_enable, 0, NULL);
			return -EINVAL;
		}
		htg_cwb_enable_call(s->cwb_enable, 0, NULL);
		/* Let any WDMA write to the stock buffers finish. */
		msleep(HTG_DISABLE_GRACE_MS);
	}
	s->cwb_info = info;

	/*
	 * Never touch buffer pointers while CWB is still enabled (possible if
	 * a stock client left it on).  mtk_drm_cwb_enable(1) would return early
	 * later and would not install our funcs/user_buffer either.
	 */
	if (READ_ONCE(info->enable)) {
		htg_cwb_enable_call(s->cwb_enable, 0, NULL);
		msleep(HTG_DISABLE_GRACE_MS);
	}

	/* comp is needed by mtk_drm_cwb_give_buf() to program the next WDMA addr. */
	if (!info->comp || !info->buffer[0].fb || !info->buffer[1].fb)
		return -EINVAL;

	/*
	 * Before we replace anything, the buffers must still be the vendor's
	 * stock ones.  This doubles as a layout/offset sanity check when a
	 * stock client created cwb_info before us.
	 */
	if (!s->full_fb[0] &&
	    (!info->buffer[0].dst_roi.width ||
	     info->buffer[0].dst_roi.width > 128 ||
	     !info->buffer[0].dst_roi.height ||
	     !info->buffer[0].addr_va || !info->buffer[0].addr_mva))
		return -EINVAL;

	if ((s->full_fb[0] || s->full_fb[1]) &&
	    (s->width != w || s->height != h))
		return -EIO;
	if (!s->full_fb[0] || !s->full_fb[1]) {
		ret = htg_alloc_full_buffers(s, w, h);
		if (ret)
			return ret;
	}
	htg_point_buffers(s);
	return 0;
}

static int htg_capture(struct htg_screen *s)
{
	struct mtk_cwb_info *info = s->cwb_info;
	unsigned long waited;

	if (!info)
		return -ENODEV;

	/*
	 * If CWB is somehow already enabled (leftover from a stock client),
	 * turn it off first: mtk_drm_cwb_enable(1) returns early when
	 * enable == 1 and would not install our funcs/user_buffer.
	 */
	if (READ_ONCE(info->enable)) {
		htg_cwb_enable_call(s->cwb_enable, 0, NULL);
		msleep(HTG_DISABLE_GRACE_MS);
	}

	s->frame_valid = false;
	info->copy_w = 0;
	info->copy_h = 0;
	info->user_buffer = NULL;
	info->type = IMAGE_ONLY;

	/*
	 * Warm-up: connect the CWB path while user_buffer is NULL.
	 *
	 * give_buf() returns before touching the next-buffer address when
	 * user_buffer is NULL, so the WDMA keeps writing the same full-size
	 * buffer and copy_w/copy_h settle at the full screen size.  We then
	 * arm the copy for one frame.
	 *
	 * This also sidesteps the vendor's dual-pipe next-address handling
	 * (give_buf() uses the same base address for both pipes instead of
	 * adding the right-half offset); we only need the frame that the path
	 * connect configured, not the alternated next buffer.
	 */
	if (!htg_cwb_enable_call(s->cwb_enable, 1, &htg_cwb_funcs))
		return -ENODEV;
	msleep(HTG_WARMUP_MS);

	reinit_completion(&htg_copy_done);
	WRITE_ONCE(s->waiting, true);
	/* Make sure the waiting=true store is visible before arming the copy. */
	smp_wmb();
	info->user_buffer = s->ppm;

	waited = wait_for_completion_timeout(&htg_copy_done,
					     msecs_to_jiffies(HTG_PPM_TIMEOUT_MS));
	/* Disable on every path; the CWB path disconnect follows the next commit. */
	htg_cwb_enable_call(s->cwb_enable, 0, &htg_cwb_funcs);

	if (!waited) {
		WRITE_ONCE(s->waiting, false);
		/* Let an in-flight vendor memcpy finish before the next capture. */
		msleep(HTG_DISABLE_GRACE_MS);
		info->user_buffer = NULL;
		return -ETIMEDOUT;
	}

	if (info->copy_w != s->width || info->copy_h != s->height) {
		info->user_buffer = NULL;
		return -EIO;
	}

	s->frame_valid = true;
	return 0;
}

static ssize_t htg_write(struct file *file, const char __user *ubuf,
			 size_t count, loff_t *ppos)
{
	char cmd[HTG_CMD_MAX];
	int ret;

	if (count >= sizeof(cmd))
		return -EINVAL;
	if (copy_from_user(cmd, ubuf, count))
		return -EFAULT;
	cmd[count] = '\0';
	strim(cmd);

	if (!strcmp(cmd, "capture")) {
		mutex_lock(&htg.lock);
		ret = htg_prepare(&htg);
		if (!ret)
			ret = htg_capture(&htg);
		mutex_unlock(&htg.lock);
		return ret ? ret : (ssize_t)count;
	}

	if (!strcmp(cmd, "free")) {
		mutex_lock(&htg.lock);
		htg.frame_valid = false;
		mutex_unlock(&htg.lock);
		return (ssize_t)count;
	}

	return -EINVAL;
}

static ssize_t htg_read(struct file *file, char __user *ubuf,
			size_t count, loff_t *ppos)
{
	char header[64];
	int hlen;
	size_t n, off;
	ssize_t ret = 0;

	mutex_lock(&htg.lock);
	if (!htg.frame_valid || !htg.ppm) {
		mutex_unlock(&htg.lock);
		return 0;
	}
	if (*ppos < 0) {
		ret = -EINVAL;
		goto out;
	}

	hlen = scnprintf(header, sizeof(header), "P6\n%u %u\n255\n",
			 htg.width, htg.height);
	if (*ppos < (loff_t)hlen) {
		n = min(count, (size_t)hlen - (size_t)*ppos);
		if (copy_to_user(ubuf, header + (size_t)*ppos, n)) {
			ret = -EFAULT;
			goto out;
		}
		*ppos += n;
		ret = (ssize_t)n;
		goto out;
	}

	off = (size_t)*ppos - (size_t)hlen;
	if (off >= htg.ppm_len) {
		ret = 0;
		goto out;
	}
	n = min(count, htg.ppm_len - off);
	if (copy_to_user(ubuf, htg.ppm + off, n)) {
		ret = -EFAULT;
		goto out;
	}
	*ppos += n;
	ret = (ssize_t)n;

out:
	mutex_unlock(&htg.lock);
	return ret;
}

static const struct file_operations htg_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = htg_read,
	.write = htg_write,
	.llseek = default_llseek,
};

static int __init htg_screen_test_init(void)
{
	memset(&htg, 0, sizeof(htg));
	mutex_init(&htg.lock);
	init_completion(&htg_copy_done);

	htg_dentry = debugfs_create_file("htfg_screen_test", 0600, NULL, NULL,
					 &htg_fops);
	if (IS_ERR_OR_NULL(htg_dentry)) {
		htg_dentry = NULL;
		return 0;
	}
	return 0;
}
late_initcall(htg_screen_test_init);

static void __exit htg_screen_test_exit(void)
{
	debugfs_remove(htg_dentry);
	htg_dentry = NULL;

	if (!htg.symbols_ok)
		return;

	/*
	 * Built-in drivers never unload; this is only for completeness.
	 * Deliberately do not free the full framebuffers or the PPM buffer:
	 * enable(0) only clears a flag and the CWB path is disconnected on the
	 * next display commit, so an in-flight WDMA write may still target
	 * them.  Leaking a few MB on an impossible unload path is the safe
	 * choice.
	 */
	htg_cwb_enable_call(htg.cwb_enable, 0, NULL);
}
module_exit(htg_screen_test_exit);

__HTFG_EOF_C__
cat > "$SRC/htfg_screen_test.h" <<'__HTFG_EOF_H__'
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HTFG_Kernel_Original_Screenshot Stage 2A test driver - private definitions.
 *
 * TEST-ONLY. This header is not exported to include/linux and is not part of
 * HTFG or HTFG_Kernel_Original.
 *
 * The structures below are byte-for-byte copies of the vendor mediatek-drm
 * definitions from OnePlusOSS android_kernel_5.10_oneplus_mt6895, branch
 * oneplus/mt6895_v_15.0.0_ace_race (drivers/gpu/drm/mediatek/mediatek_v2/
 * mtk_drm_crtc.h and mtk_drm_gem.h).  They must stay identical to the module
 * that is actually running on the device; the enum/struct tag names matter for
 * CFI (see the copy_done type id below).
 *
 * Confirmed on 2026-11-11 by disassembling the device's mediatek-drm.ko:
 *   struct mtk_drm_crtc starts with struct drm_crtc base, and every CWB
 *   helper reaches cwb_info through [crtc + 0x10 + 0x1378], i.e.
 *
 *       cwb_info = *(void **)((char *)crtc + HTFG_CWB_INFO_OFFSET)
 *
 *   mtk_drm_cwb_monitor_thread uses [crtc + 0x1388] directly.
 */
#ifndef HTFG_SCREEN_TEST_H
#define HTFG_SCREEN_TEST_H

#include <linux/types.h>
#include <linux/dma-mapping.h>
#include <drm/drm_gem.h>
#include <drm/drm_framebuffer.h>

#define HTFG_CWB_INFO_OFFSET	0x1388

struct mtk_rect {
	int x;
	int y;
	int width;
	int height;
};

/*
 * CFI: the vendor module contains
 *   __typeid__ZTSFvPv15CWB_BUFFER_TYPEE_global_addr
 * i.e. the canonical function type is "void (void *, CWB_BUFFER_TYPE)".
 * The enum tag, enumerator order and function signature must match exactly or
 * the vendor's indirect call to copy_done will fail the CFI check.
 */
enum CWB_BUFFER_TYPE {
	IMAGE_ONLY,
	CARRY_METADATA,
	BUFFER_TYPE_NR,
};

/* Layout only: the actual vendor enumerator values are irrelevant here. */
enum addon_scenario {
	ADDON_SCN_NONE = 0,
};

struct mtk_cwb_buffer_info {
	struct mtk_rect dst_roi;
	dma_addr_t addr_mva;
	u64 addr_va;
	struct drm_framebuffer *fb;
	unsigned long long timestamp;
};

struct mtk_cwb_funcs {
	void (*get_buffer)(void **buffer);
	void (*copy_done)(void *buffer, enum CWB_BUFFER_TYPE type);
};

struct mtk_ddp_comp;

struct mtk_cwb_info {
	unsigned int enable;
	struct mtk_rect src_roi;
	unsigned int count;
	bool is_sec;
	unsigned int buf_idx;
	struct mtk_cwb_buffer_info buffer[2];
	unsigned int copy_w;
	unsigned int copy_h;
	enum addon_scenario scn;
	struct mtk_ddp_comp *comp;
	void *user_buffer;
	enum CWB_BUFFER_TYPE type;
	const struct mtk_cwb_funcs *funcs;
};

struct mtk_drm_gem_obj {
	struct drm_gem_object base;
	void *cookie;
	void *kvaddr;
	dma_addr_t dma_addr;
	size_t size;
	unsigned long dma_attrs;
	struct sg_table *sg;
	bool sec;
	bool is_dumb;
};

#endif /* HTFG_SCREEN_TEST_H */

__HTFG_EOF_H__
cat > "$SRC/Kconfig" <<'__HTFG_EOF_K__'
# SPDX-License-Identifier: GPL-2.0
#
# HTFG_Kernel_Original_Screenshot Stage 2A test driver.
# TEST-ONLY: this option must never be enabled in a shipping kernel.

config HTFG_SCREEN_TEST
	bool "HTFG Stage 2 screen capture test driver (test kernels only)"
	depends on DRM && DEBUG_FS && KALLSYMS_ALL
	default y
	help
	  Independent built-in test driver for the HTFG screenshot feasibility
	  project.  It reaches the vendor mediatek-drm CWB/WDMA helpers through
	  kallsyms_lookup_name(), replaces the stock 128-wide CWB buffers with
	  full-screen MTK GEM framebuffers, and exposes a root-only debugfs node
	  for capture/read.

	  This is a prototype scaffold, not the final HTFG interface.  It does
	  not include HTFG headers, does not register a prctl operation and must
	  not be shipped.

__HTFG_EOF_K__
cat > "$SRC/Makefile" <<'__HTFG_EOF_M__'
# SPDX-License-Identifier: GPL-2.0
#
# HTFG_Kernel_Original_Screenshot Stage 2A test driver (TEST-ONLY).
# This Makefile is copied into drivers/htfg_screen_test/Makefile by
# test_htfg_apply.sh; it is not the HTFG driver Makefile.

obj-$(CONFIG_HTFG_SCREEN_TEST) += htfg_screen_test.o

__HTFG_EOF_M__

# ---- locate the kernel tree (same logic as the official script) ----
if [ -f kernel/sys.c ]; then
    :
elif [ -f kernel_workspace/kernel_platform/common/kernel/sys.c ]; then
    cd kernel_workspace/kernel_platform/common
else
    echo "ERROR: HTFG screen-test: kernel tree not found (cwd $(pwd))"
    exit 1
fi
echo "HTFG screen-test: tree=$(pwd) rev=${REV:0:12}"

# ---- install / hook / self-check ----
mkdir -p drivers/htfg_screen_test
cp -f "$SRC/htfg_screen_test.c" "$SRC/htfg_screen_test.h" \
      "$SRC/Kconfig" "$SRC/Makefile" drivers/htfg_screen_test/

grep -q 'drivers/htfg_screen_test/Kconfig' drivers/Kconfig || \
    sed -i '/endmenu/i source "drivers/htfg_screen_test/Kconfig"' drivers/Kconfig

grep -qF 'obj-$(CONFIG_HTFG_SCREEN_TEST) += htfg_screen_test/' drivers/Makefile || \
    sed -i '$a obj-$(CONFIG_HTFG_SCREEN_TEST) += htfg_screen_test/' drivers/Makefile

grep -q '^CONFIG_HTFG_SCREEN_TEST=y' arch/arm64/configs/gki_defconfig || \
    echo 'CONFIG_HTFG_SCREEN_TEST=y' >> arch/arm64/configs/gki_defconfig

FAIL=0
chk() {
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
    "$(grep -cF 'obj-$(CONFIG_HTFG_SCREEN_TEST) += htfg_screen_test/' drivers/Makefile || true)"
chk "gki_defconfig CONFIG_HTFG_SCREEN_TEST=y" 1 \
    "$(grep -c '^CONFIG_HTFG_SCREEN_TEST=y' arch/arm64/configs/gki_defconfig || true)"
chk "test driver source files" 4 \
    "$(ls -1 drivers/htfg_screen_test/htfg_screen_test.c \
              drivers/htfg_screen_test/htfg_screen_test.h \
              drivers/htfg_screen_test/Kconfig \
              drivers/htfg_screen_test/Makefile 2>/dev/null | wc -l)"

if [ "$FAIL" != 0 ]; then
    echo "ERROR: HTFG screen-test: injection self-check failed"
    exit 1
fi

ls -l drivers/htfg_screen_test/
echo "OK: HTFG screen-test driver injected (rev ${REV:0:12})"
