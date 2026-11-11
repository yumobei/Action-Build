/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HTFG Phase 2 沙盒：全屏抓帧模块的私有定义（vendor 结构体副本）。
 *
 * SANDBOX-ONLY. 本文件只在 HTFG_Kernel_Original_Screenshot/phase2 内使用，
 * 不属于正式 HTFG / HTFG_Kernel_Original。
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
#ifndef HTFG_SCREEN_H
#define HTFG_SCREEN_H

#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/dma-mapping.h>
#include <linux/htfg.h>
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

/* 抓帧模块入口（htfg.c 调用；协议定义见 <linux/htfg.h> 的 SCREEN 段） */
int htg_screen_init(void);
int htg_screen_capture(struct htfg_screen_info *info);
int htg_screen_read(uint64_t offset, void __user *ubuf, uint32_t len,
		    uint32_t *copied);
void htg_screen_free(void);

#endif /* HTFG_SCREEN_H */
