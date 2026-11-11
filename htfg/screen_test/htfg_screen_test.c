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
