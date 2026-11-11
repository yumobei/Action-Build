/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HTFG —— 内核侧通道 ABI 定义（协议 v2：ping + 读内存三原语 + 触摸查询/注入）
 *
 * 放置位置：内核树的 include/linux/htfg.h
 *
 * 本头文件是**内核与用户态共用的单一来源**：
 *   - 内核侧：drivers/htfg/htfg.c、kernel/sys.c（经 patch_sysc.py 加钩子）
 *   - 用户态：tools/htfgctl/htfgctl.c 直接 #include 本文件（不再手工抄写）
 *
 * 唯一无法 include 本文件的是 MyApplication 的 Java 侧（MainActivity.java）：
 * 其中的常量与结构体偏移为手工抄写，抄写处有同步注释；运行时由 op.tag
 * （HTFG_ABI_TAG）校验兜底——Java 侧若漏改，自测 J1 会当场报 -EINVAL。
 *
 * 协议 v1（第 1 步）的标量 ping 一字未动，继续可用：
 *     prctl(HTFG_PRCTL_MAGIC, HTFG_CMD_PING, 0, 0, 0) == HTFG_PING_REPLY
 * 协议 v2（第 2 步）：
 *     struct htfg_op op = { .op = ..., .tag = HTFG_ABI_TAG, ... };
 *     prctl(HTFG_PRCTL_MAGIC, (unsigned long)&op, 0, 0, 0);
 *     → 返回 0 表示协议级成功，结果在 op.out（0 或负 errno，按 int32 读）。
 */
#ifndef _LINUX_HTFG_H
#define _LINUX_HTFG_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/* prctl() 的第一个参数（option）使用这个魔数：'HTFG' = 0x48544647 = 1213482567
 * 选它是因为它是正数，能安全地同时用 int / long 返回给用户态。 */
#define HTFG_PRCTL_MAGIC	0x48544647

/* v1 标量命令，放在 prctl() 的第二个参数 */
#define HTFG_CMD_PING		1

/* HTFG_CMD_PING 的返回值：直接用系统调用返回值返回，不需要用户态指针 */
#define HTFG_PING_REPLY		HTFG_PRCTL_MAGIC

/* v2 结构体协议的 tag：'HTF2' = 0x48544632
 * 双重作用：ABI 版本握手 + 快速排除"垃圾指针被误当作 op 结构体"。 */
#define HTFG_ABI_TAG		0x48544632

/* ------------------------------------------------------------------ op 表 */
#define HTFG_OP_PING		1	/* 结构体版 ping：count = HTFG_PRCTL_MAGIC */
#define HTFG_OP_READ_MEM	2	/* 读目标进程一段内存（只读原语） */
#define HTFG_OP_FIND_PID	3	/* 按包名（argv[0] 精确匹配）找主进程 pid */
#define HTFG_OP_GET_VMAS	4	/* 枚举目标进程的内存映射 */
#define HTFG_OP_TOUCH_DEV	5	/* 查询触摸屏 input 设备信息（只读） */
#define HTFG_OP_TOUCH_SEND	6	/* 注入触摸事件帧（本通道首个带副作用的原语） */

/* ------------------------------------------------------------------ 上限 */
#define HTFG_READ_MAX_LEN	(1024 * 1024)	/* READ_MEM 单次上限 1 MiB */
#define HTFG_FIND_LEN_MAX	255		/* FIND_PID 包名长度上限（含结尾 NUL） */
#define HTFG_VMA_NAME_LEN	48		/* 映射名字段长度（含结尾 NUL） */

#define HTFG_OP_SIZE		40	/* sizeof(struct htfg_op)，双端 static_assert */
#define HTFG_VMA_SIZE		88	/* sizeof(struct htfg_vma)，双端 static_assert */

/* TOUCH（op 5/6）规模与位图（第 5 步，2026-10-12） */
#define HTFG_TOUCH_NAME_LEN	48	/* 触摸屏名字段长度（含结尾 NUL） */
#define HTFG_TOUCH_SYSFS_LEN	16	/* sysfs 设备名（形如 "input5"，含 NUL） */
#define HTFG_TOUCH_EV_MAX	64	/* TOUCH_SEND 单次事件条数上限 */
#define HTFG_TOUCH_EV_SIZE	12	/* sizeof(struct htfg_touch_ev) */
#define HTFG_TOUCH_INFO_SIZE	144	/* sizeof(struct htfg_touch_info) */

/* struct htfg_touch_info.caps 位：本设备实际支持的事件码 */
#define HTFG_TOUCH_CAP_MT_SLOT		(1u << 0)
#define HTFG_TOUCH_CAP_MT_TRACKING_ID	(1u << 1)
#define HTFG_TOUCH_CAP_MT_POSITION_X	(1u << 2)
#define HTFG_TOUCH_CAP_MT_POSITION_Y	(1u << 3)
#define HTFG_TOUCH_CAP_MT_TOUCH_MAJOR	(1u << 4)
#define HTFG_TOUCH_CAP_MT_TOUCH_MINOR	(1u << 5)
#define HTFG_TOUCH_CAP_MT_PRESSURE	(1u << 6)
#define HTFG_TOUCH_CAP_BTN_TOUCH	(1u << 7)
#define HTFG_TOUCH_CAP_BTN_TOOL_FINGER	(1u << 8)

/* struct htfg_touch_info.mt_flags 位（内核 INPUT_MT_* 原值镜像） */
#define HTFG_TOUCH_MTF_POINTER		0x1
#define HTFG_TOUCH_MTF_DIRECT		0x2
#define HTFG_TOUCH_MTF_DROP_UNUSED	0x4	/* 置位：真实手指上报帧会让注入触点被抬起 */
#define HTFG_TOUCH_MTF_TRACK		0x8
#define HTFG_TOUCH_MTF_SEMI_MT		0x10

/* struct htfg_vma.prot 位（口径与 /proc/maps 前 4 列一致） */
#define HTFG_VMA_READ		1
#define HTFG_VMA_WRITE		2
#define HTFG_VMA_EXEC		4
#define HTFG_VMA_SHARED		8	/* 第 4 列 s/p：内核判据 VM_MAYSHARE（非 VM_SHARED） */

/* struct htfg_vma.kind */
#define HTFG_VMA_KIND_ANON	0	/* 匿名、无名 */
#define HTFG_VMA_KIND_FILE	1	/* 文件映射（name = basename） */
#define HTFG_VMA_KIND_ANON_NAMED 2	/* 匿名有名，即 [anon:...]（name = 原始名） */

/*
 * v2 主结构体（40 字节，布局固定，32/64 位调用方通用）。
 *
 * 入参/出参约定（按 op 区分，详见各原语文档）：
 *   READ_MEM : 入 pid/addr/buf/len；出 count=实际读到字节数（buf 为用户缓冲）。
 *              present-only：只读已驻留页，遇到非驻留页立即截断（count < len），
 *              绝不触发缺页/换入，也不填零
 *   FIND_PID : 入 buf=包名字符串、len=含 NUL 长度；出 pid=命中 pid、count=0
 *   GET_VMAS : 入 pid、buf=条目数组、len=字节容量；出 count=写入条目数
 *   TOUCH_DEV: 入 pid=命中序号、buf=struct htfg_touch_info、len=容量；
 *              出 count=命中总数、pid=实际命中序号
 *   TOUCH_SEND: 入 pid=设备命中序号、buf=struct htfg_touch_ev 数组、
 *               len=字节数；出 count=实际交给 input_event() 的条数
 *
 * 协议级结果一律走 out：0 = 成功；负值 = -errno（按 int32 读）。
 * 处理完成（无论 op 本身成败）系统调用返回 0；只有"结构体指针坏 / 身份门不通过"
 * 这类协议级失败才返回负 errno（此时不触碰结构体）。
 *
 * 身份门失败统一返回 -EINVAL（与 stock 内核的未知 prctl option 不可区分）。
 * 验签缓存未命中时本次同样返回 -EINVAL，但内核已把验签投进 system_wq：
 * 客户端应在"通道级 EINVAL"上做短重试（约 10×2 ms），不重试 op 级 out=-EINVAL。
 *
 * 身份门里的"验签"准确含义 = APK 签名证书指纹固定（certificate pinning）：
 * 取调用者已安装 base.apk v2 签名块中第一张证书的 SHA-256 与内置指纹比对；
 * 不做公钥验签、不校验 APK 内容摘要。信任前提 = PackageManager 安装时已
 * 验签 + /data/app 下 APK 不可变（普通 App 无法替换已安装 APK）。
 */
struct htfg_op {
	uint32_t op;	/* 入：HTFG_OP_* */
	uint32_t pid;	/* 入：目标 pid；出：FIND_PID 命中的 pid */
	uint64_t addr;	/* 入：READ_MEM 目标地址（目标进程地址空间） */
	uint64_t buf;	/* 入：调用者缓冲区地址（本进程地址空间） */
	uint32_t len;	/* 入：长度 / 容量（语义按 op，见上） */
	uint32_t count;	/* 出：结果数量（语义按 op，见上） */
	uint32_t tag;	/* 入：固定 HTFG_ABI_TAG，不匹配 → out=-EINVAL */
	uint32_t out;	/* 出：0 或负 errno（按 int32 解释） */
};

/*
 * v2 GET_VMAS 条目（88 字节）。
 *
 * 名字语义：
 *   - kind=1（文件映射）：name = basename（如 libart.so、boot.art），
 *     读不到（路径过长等）则留空；
 *   - kind=2（匿名有名，即 /proc/maps 里的 [anon:xxx]）：name = 原始名
 *     （去掉 [anon: 前缀与结尾 ]）；
 *   - 其余：name 全 0。
 *
 * 预留位说明：kind/pgoff/flags 供 M0.5 校准后按需使用；如 M1 开工前发现缺字段，
 * 协议有 tag 版本号兜底，可小改一版。
 */
struct htfg_vma {
	uint64_t start;		/* 起始地址（含） */
	uint64_t end;		/* 结束地址（不含） */
	uint64_t flags;		/* 原样 vm_flags（u64：arm64 有 >32 位的位） */
	uint64_t pgoff;		/* 文件偏移（字节）= vm_pgoff << PAGE_SHIFT */
	uint32_t prot;		/* HTFG_VMA_READ|WRITE|EXEC|SHARED 位或（口径同 /proc/maps） */
	uint32_t kind;		/* HTFG_VMA_KIND_* */
	char     name[HTFG_VMA_NAME_LEN];	/* NUL 结尾 */
};

/*
 * v2 TOUCH 协议（第 5 步，op 5/6）。
 *
 * 注入管线与"App 直写 /dev/input/eventN"（evdev_write → input_inject_event）
 * 在输入核心处同一路径：事件源设备、时间戳（投递时刻 CLOCK_MONOTONIC）、
 * 框架解析完全一致；不新建设备、不注册 input_handler、不建 proc/sysfs 条目。
 *
 * TOUCH_DEV（op 5）——查询触摸屏：
 *   入：pid = 想取的命中序号（0 基）；buf = struct htfg_touch_info 指针、
 *       len = 容量（≥ HTFG_TOUCH_INFO_SIZE）；
 *       调用方须先把 info.size 填为 HTFG_TOUCH_INFO_SIZE（ABI 自检）。
 *   出：count = 命中总数；pid = 实际命中序号；info 其余字段填完。
 *   错误：-ENODEV（无命中/序号越界）/ -ENOSPC（容量不足）/ -EINVAL（size
 *         不符）/ -EFAULT。
 *   设备判据 = EV_ABS ∧ ABS_MT_SLOT ∧ ABS_MT_POSITION_X ∧ ABS_MT_POSITION_Y
 *   ∧ dev->mt 非空（沿用触控项目模块的"三特征"启发式）。
 *
 * TOUCH_SEND（op 6）——注入事件帧（先全量校验、后注入）：
 *   入：pid = 设备命中序号；buf = struct htfg_touch_ev 数组、
 *       len = 字节数（>0、12 的倍数、≤ HTFG_TOUCH_EV_MAX*12）。
 *   出：count = 实际交给 input_event() 的条数。
 *   错误：-EINVAL（结构性/值域错误，整批零注入）/ -ENODEV / -EFAULT /
 *         -EBUSY（设备被他人 grab，注入会被输入核心整条丢弃）。
 *   白名单码（10 个）：SYN_REPORT、BTN_TOUCH、BTN_TOOL_FINGER、
 *   ABS_MT_SLOT、ABS_MT_TRACKING_ID、ABS_MT_POSITION_X/Y、ABS_MT_PRESSURE、
 *   ABS_MT_TOUCH_MAJOR/MINOR；"核心四码"（SLOT/TRACKING_ID/X/Y）设备必须
 *   支持（否则 -EINVAL），其余白名单码设备不支持时静默跳过——与输入核心
 *   对被支持码的静默丢弃行为一致（input_get_disposition），count 如实少计。
 */
struct htfg_touch_ev {		/* 12 字节 */
	uint32_t type;		/* 入：EV_SYN(0) / EV_KEY(1) / EV_ABS(3) */
	uint32_t code;		/* 入：白名单码（见上） */
	int32_t  value;		/* 入：值（按设备 absinfo 校验） */
};

struct htfg_touch_info {	/* 144 字节 */
	uint32_t size;		/* 入：HTFG_TOUCH_INFO_SIZE（ABI 自检） */
	char     name[HTFG_TOUCH_NAME_LEN];	/* dev->name，NUL 结尾 */
	int32_t  x_min, x_max;			/* ABS_MT_POSITION_X 的 absinfo */
	int32_t  y_min, y_max;			/* ABS_MT_POSITION_Y */
	int32_t  major_min, major_max;		/* ABS_MT_TOUCH_MAJOR（不支持则全 0） */
	int32_t  minor_min, minor_max;		/* ABS_MT_TOUCH_MINOR（不支持则全 0） */
	int32_t  pressure_min, pressure_max;	/* ABS_MT_PRESSURE（不支持则全 0） */
	uint32_t num_slots;		/* dev->mt->num_slots */
	uint32_t mt_flags;		/* dev->mt->flags 原值（HTFG_TOUCH_MTF_*） */
	uint32_t caps;			/* HTFG_TOUCH_CAP_* 位或 */
	uint32_t dev_index;		/* 出：本次命中的序号（0 基） */
	uint32_t dev_matches;		/* 出：命中总数（>1 时需按序号选取） */
	char     sysfs_name[HTFG_TOUCH_SYSFS_LEN];	/* 形如 "input5"，NUL 结尾 */
	uint32_t reserved[4];		/* 预留（当前填 0） */
};

#ifdef __KERNEL__
long ksu_htfg_prctl(unsigned long arg2, unsigned long arg3,
		unsigned long arg4, unsigned long arg5);
#endif

#endif /* _LINUX_HTFG_H */
