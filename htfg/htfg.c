// SPDX-License-Identifier: GPL-2.0
/*
 * HTFG —— 内核侧通道（第 2 步：ping + 读内存三原语；第 5 步：触摸查询/注入）
 *
 * 放置位置：内核树的 drivers/htfg/htfg.c
 *
 * 协议与常量定义见 include/linux/htfg.h（内核/用户态共用单一来源）。
 *
 * 本步新增的全部是**只读**原语：
 *   READ_MEM  —— 读任意进程一段内存（单 VMA 截断、按页分块、present-only、绝不写）；
 *   FIND_PID  —— 按包名（argv[0] 精确匹配）找主进程 pid；
 *   GET_VMAS  —— 枚举目标进程内存映射（分批：锁内只填内核缓冲、锁外 copy_to_user）。
 * 第 1 步的标量 ping 行为一字未改（协议 v1 兼容）。
 *
 * 2026-10-12（第 5 步）增补：TOUCH_DEV / TOUCH_SEND 两个 op（触摸屏查询与
 * 触摸事件注入，见下方 TOUCH 段）。**TOUCH_SEND 是本通道首个带副作用的
 * 原语**——它只把事件注入真实触摸屏 input_dev 的事件管线（与"App 直写
 * evdev 节点"经 input_inject_event 在输入核心处同一路径），不写任何进程
 * 内存、不写文件、不新建设备/进程/proc 条目。
 *
 * 2026-10-06（M2.3）增补：身份判据由「工具 uid 白名单」扩展为「工具 uid ∪
 * 内核 APK 签名证书指纹固定」——见 SIGN 段（内核直读调用者包的 base.apk、
 * 取 v2 签名块首张证书的 SHA-256 与编译期指纹比对；不限定包名，一钥多 App）。
 * 这是 certificate pinning，不是完整 v2 验签：不验 signature record、不校验
 * APK 内容摘要；信任前提 = PackageManager 安装时验签 + /data/app 不可变。
 * prctl 的分发顺序与协议 ABI 均不变。
 *
 * 2026-10-19 增补（反检测整改，协议/ABI 均不变）：三条目标内存读取路径
 * （READ_MEM / GET_VMAS 匿名名 / FIND_PID argv[0]）全部改为 present-only，
 * 不触发缺页/换入；身份门未授权改为 -EINVAL 且冷验签移到 system_wq 异步。
 *
 * 纪律（与第 1 步相同的验收口径）：
 *   - 零 printk / 零 WARN / 零 BUG_ON（dmesg 零输出是硬性要求）；
 *   - 钩子位于 prctl() 系统调用上下文（LSM 钩子之前）——普通进程上下文，允许睡眠，
 *     但每个原语都把单次时长压得很短（READ_MEM ≤1 MiB 分页、GET_VMAS 一页一批）；
 *   - 目标内存一律 present-only（2026-10-19 起）：只用 follow_page 读"已驻留页"，
 *     绝不触发缺页/换入（access_remote_vm / GUP / get_cmdline 均已移除）。目标对
 *     自己的页做 MADV_PAGEOUT 再盯 RSS/Swap 的 swap canary 因此看不到任何回增；
 *     非驻留页如实截断（count < len），不填零、不伪造数据；
 *   - 锁序钉死：find_get_task_by_vpid → get_task_mm → mmap_read_lock{find_vma/
 *     follow_page/kmap/memcpy} → unlock → copy_*_user → mmput → put_task_struct。
 *     绝不持 mmap 锁调用 copy_*_user——自读（pid == 自己）时缺页会递归请求同一把
 *     mmap 读锁而死锁；
 *   - 只读为主：除 TOUCH_SEND（唯一副作用原语，作用面仅限触摸屏事件管线）外，
 *     全文件无 FOLL_WRITE、无对目标地址的任何写操作；
 *   - 身份门对外统一返回 -EINVAL（与 stock 未知 prctl option 不可区分）；冷验签在
 *     system_wq 里异步执行，调用者线程不做 override_creds/文件 I/O；
 *   - 所有函数 static、htfg_ 前缀；变量声明放块首（本树开 -Wdeclaration-after-statement）；
 *   - ksu_htfg_prctl 保持 noinline（System.map 校验依赖）。
 */

#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/err.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <crypto/hash.h>
#include <crypto/sha.h>
#include <linux/device.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/htfg.h>

/* ABI 布局双端校验（用户态侧 htfgctl.c 里有相同断言） */
static_assert(sizeof(struct htfg_op) == HTFG_OP_SIZE, "htfg_op size");
static_assert(sizeof(struct htfg_vma) == HTFG_VMA_SIZE, "htfg_vma size");
static_assert(sizeof(struct htfg_touch_ev) == HTFG_TOUCH_EV_SIZE,
	      "htfg_touch_ev size");
static_assert(sizeof(struct htfg_touch_info) == HTFG_TOUCH_INFO_SIZE,
	      "htfg_touch_info size");

/* FIND_PID：comm 前缀预筛的候选上限、兜底全量扫描的 pid 上限 */
#define HTFG_FIND_CAND_MAX	64
#define HTFG_FIND_PID_MAX	4096

/* GET_VMAS：每批填充条数（一页内核缓冲；46 = 4096 / 88） */
#define HTFG_VMA_BATCH_MAX	(PAGE_SIZE / HTFG_VMA_SIZE)

/* SIGN：APK 签名证书指纹（htai.jks，2026-10-06 提取；apksigner 与独立解包
 * 脚本双源核对一致）。证书 DER 大小 + SHA-256 双匹配。
 * 判据 = 「调用者已安装的 APK 由 htai 证书签名」，**不限定包名**——同一把
 * 密钥可签多个 App（一钥多 App，均为可放行的取数客户端；私钥即通行证）。 */
#define HTFG_SIGN_CERT_SIZE	790
#define HTFG_SIGN_CERT_SHA256	"e0905b9c2acb623acadf37e8d63899e741ef3e1d088111f0b806375881cb11e5"

/* SIGN：规模上限与缓存参数 */
#define HTFG_SIGN_CERT_MAX	1024	/* 证书缓冲（当前 790B；换更大证书同步加大） */
#define HTFG_SIGN_ENTRY_MAX	4096	/* v1 检查最多遍历的 ZIP 条目数 */
#define HTFG_SIGN_PAIR_MAX	4096	/* v2 签名块最多遍历的 ID-value 对数
					 * （合法 APK 通常 1~2 对；上限防病态块
					 * 长期占用 system_wq worker） */
#define HTFG_PATH_MAX		384	/* apk 全路径缓冲（参考实现 DATA_PATH_LEN 同款） */
#define HTFG_PKG_MAX		256	/* 包名缓冲 */
#define HTFG_PL_READ_MAX	(1 << 20)	/* packages.list 读取上限 */
#define HTFG_APK_SUB_MAX	512	/* /data/app 顶层 ~~* 子目录收集上限（实测 41 包） */
#define HTFG_APK_SUB_NAME	32	/* 子目录名缓冲（实际形如 ~~<16B base64>==，26 字符） */
#define HTFG_VERIFY_SLOTS	8	/* 验证缓存槽位（uid 表；多 App 并存留裕量） */
#define HTFG_VERIFY_TTL		(10 * HZ)	/* 正结果 TTL：过期后下次调用重验 */
#define HTFG_VERIFY_NEG_TTL	(5 * HZ)	/* 负结果 TTL（防探测刷） */

/*
 * 工具身份白名单（身份判据之一；**不含任何 App uid**；SIGN 段是正式 App 的正式判据）。
 *
 * 0(root) 与 2000(shell) 用于命令行验证；正式取数 App **不**走静态 uid——
 * 走 SIGN 段内核 APK 验签（跨设备/重装零维护，uid 变化不影响；不限定包名，
 * 见 SIGN 段）。
 *
 * 纪律（2026-10-11 定）：**白名单里不得再写任何 App 的静态 uid**。App 的
 * uid 本质是"第几个安装位"的编号（如 u0_a312 = 第 313 个装上的 App），
 * 换台设备就落到另一个毫不相干的 App 头上——等于把任意进程读内存权限
 * 发给随机 App。此前用于真机校准的测试 App（10312）已随校准完结移除。
 */
static bool htfg_uid_allowed(void)
{
	kuid_t uid = current_euid();

	return uid_eq(uid, GLOBAL_ROOT_UID) ||
	       uid_eq(uid, KUIDT_INIT(2000));
}

/* ============================================================ present-only */

/*
 * 取 va 所属页（仅已驻留时返回；不触发缺页/换入）。
 * 调用时必须持有 mm 的 mmap 读锁。成功返回带引用的 page（调用方 put_page）；
 * 非驻留页（swap/未提交/DONTNEED）、零页、特殊映射、取页失败均返回 NULL。
 * 注：非 FOLL_WRITE 时 follow_page 对 COW 空洞返回 NULL 而非 ERR_PTR；
 * 万一返回 ERR_PTR（引用计数溢出等）也按不可读处理，绝不 fault-in。
 */
static struct page *htfg_get_present_page(struct mm_struct *mm, unsigned long va)
{
	struct vm_area_struct *vma;
	struct page *page;

	vma = find_vma(mm, va);
	if (!vma || va < vma->vm_start || va >= vma->vm_end)
		return NULL;
	page = follow_page(vma, va & PAGE_MASK, FOLL_GET | FOLL_FORCE);
	return IS_ERR_OR_NULL(page) ? NULL : page;
}

/*
 * 页内偏移：arm64 无 HIGHMEM，kmap 直通。两种情形各自自洽：
 * - follow_page 返回 compound head 时（GUP/THP 契约），THP/hugetlb 的虚拟
 *   区间按 compound 大小对齐，用 va & (compound_size - 1)；
 * - 返回普通页（order-0，或某些版本的 PTE-mapped tail）时用 4K 偏移。
 */
static unsigned long htfg_page_off(struct page *page, unsigned long va)
{
	if (PageHead(page))
		return va & ((PAGE_SIZE << compound_order(page)) - 1);
	return va & ~PAGE_MASK;
}

/*
 * 持 mm 的 mmap 读锁调用：从 addr 起最多拷贝 len 字节到内核缓冲 dst。
 * 遇到非驻留页/越界即停；返回实际拷贝字节数（可能 < len）。不 copy_to_user。
 */
static size_t htfg_read_present_locked(struct mm_struct *mm, unsigned long addr,
				       void *dst, size_t len)
{
	size_t done = 0;
	char *out = dst;

	while (done < len) {
		unsigned long va = addr + done;
		size_t chunk;
		struct page *page;
		const char *kaddr;

		page = htfg_get_present_page(mm, va);
		if (!page)
			break;
		chunk = len - done;
		if (chunk > PAGE_SIZE - (va & ~PAGE_MASK))
			chunk = PAGE_SIZE - (va & ~PAGE_MASK);
		kaddr = kmap(page);
		memcpy(out + done, kaddr + htfg_page_off(page, va), chunk);
		kunmap(page);
		put_page(page);
		done += chunk;
	}
	return done;
}

/* ============================================================ READ_MEM */

/*
 * 读目标进程 [addr, addr+len) 的一段内存（只读）。
 *
 * 语义（与协议文档一致）：
 *   - 截断到 addr 所在的那一个 VMA：超出 VMA 结尾的部分不读（count 如实）；
 *   - present-only：只读已驻留页，绝不触发缺页/换入；遇到非驻留页立即截断，
 *     不填零、不换入（目标可用 MADV_PAGEOUT + RSS/Swap 观测做 swap canary）；
 *   - 按页分块：内核临时缓冲只有一页（绝不 kmalloc(len)），读完一块拷一块；
 *     copy_to_user 一律在 mmap 锁外；
 *   - count = 实际交付字节数；len>0 而读到 0 字节 → out=-EFAULT；
 *   - FOLL_GET | FOLL_FORCE：只取引用、不写；FOLL_FORCE 对齐 /proc/pid/mem 的读语义。
 */
static void htfg_op_read_mem(struct htfg_op *kop)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned long addr;
	unsigned long end;
	unsigned long long done = 0;
	unsigned long long left;
	void *kbuf;

	if (kop->len > HTFG_READ_MAX_LEN) {
		kop->out = (uint32_t)-EINVAL;
		return;
	}
	if (kop->len == 0) {		/* 显式空读：成功、0 字节 */
		kop->count = 0;
		kop->out = 0;
		return;
	}
	if (kop->addr + kop->len < kop->addr) {		/* 地址回绕 */
		kop->out = (uint32_t)-EINVAL;
		return;
	}

	task = find_get_task_by_vpid(kop->pid);
	if (!task) {
		kop->out = (uint32_t)-ESRCH;
		return;
	}
	mm = get_task_mm(task);
	if (!mm) {			/* 内核线程 / 已死：没有地址空间 */
		kop->out = (uint32_t)-ESRCH;
		goto out_put_task;
	}
	if (kop->addr >= mm->task_size) {		/* 目标地址空间上界 */
		kop->out = (uint32_t)-EINVAL;
		goto out_mmput;
	}

	addr = (unsigned long)kop->addr;

	/* 持锁窗口里只做校验与截断；vma 指针绝不带出锁外 */
	mmap_read_lock(mm);
	vma = find_vma(mm, addr);
	if (!vma || addr < vma->vm_start) {
		mmap_read_unlock(mm);
		kop->out = (uint32_t)-EFAULT;
		goto out_mmput;
	}
	end = vma->vm_end;
	mmap_read_unlock(mm);

	left = (unsigned long long)end - addr;
	if (left > kop->len)
		left = kop->len;

	kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!kbuf) {
		kop->out = (uint32_t)-ENOMEM;
		goto out_mmput;
	}

	/*
	 * 分块读：锁内只取驻留页并拷到 1 页内核缓冲；copy_to_user 在锁外。
	 * 非驻留页（被换出/未提交/DONTNEED/零页）→ 立即截断，绝不 fault-in。
	 */
	while (done < left) {
		unsigned long va = addr + (unsigned long)done;
		unsigned long long chunk = left - done;
		struct page *page;
		const char *kaddr;

		if (chunk > PAGE_SIZE - (va & ~PAGE_MASK))
			chunk = PAGE_SIZE - (va & ~PAGE_MASK);

		mmap_read_lock(mm);
		page = htfg_get_present_page(mm, va);
		if (page) {
			kaddr = kmap(page);
			memcpy(kbuf, kaddr + htfg_page_off(page, va),
			       (size_t)chunk);
			kunmap(page);
			put_page(page);
		}
		mmap_read_unlock(mm);

		if (!page)
			break;		/* 非驻留页：如实截断，不换入 */

		if (copy_to_user((void __user *)(uintptr_t)(kop->buf + done),
				 kbuf, (unsigned long)chunk)) {
			kop->count = (uint32_t)done;	/* 只计已交付的字节 */
			kop->out = (uint32_t)-EFAULT;
			kfree(kbuf);
			goto out_mmput;
		}
		done += chunk;
	}
	kfree(kbuf);

	kop->count = (uint32_t)done;
	kop->out = done ? 0 : (uint32_t)-EFAULT;

out_mmput:
	mmput(mm);
out_put_task:
	put_task_struct(task);
}

/* ============================================================ FIND_PID */

/*
 * task 的 argv[0] 是否整串等于 name（不依赖 comm；setproctitle 覆盖后仍读
 * mm->arg_start，与 get_cmdline 同口径）。
 *
 * present-only：只读 argv 页中已驻留的部分，绝不缺页/换入；argv 页被目标
 * 自己换出时视为不匹配（不命中，而不是把它换回来）。调用时不得持 mmap 锁。
 */
static bool htfg_cmdline_is(struct task_struct *task, const char *name,
			    unsigned int namelen)
{
	struct mm_struct *mm;
	unsigned long arg_start;
	unsigned long arg_end;
	char buf[HTFG_FIND_LEN_MAX + 1];
	size_t len = (size_t)namelen + 1;
	bool ok = false;

	if (len < 2 || len > sizeof(buf))
		return false;

	mm = get_task_mm(task);
	if (!mm)
		return false;

	mmap_read_lock(mm);
	arg_start = mm->arg_start;
	arg_end = mm->arg_end;
	if (arg_start && arg_end > arg_start &&
	    arg_end - arg_start >= len &&
	    htfg_read_present_locked(mm, arg_start, buf, len) == len)
		ok = (buf[namelen] == '\0' &&
		      memcmp(buf, name, namelen) == 0);
	mmap_read_unlock(mm);
	mmput(mm);
	return ok;
}

/*
 * 按包名找主进程 pid。
 *
 * 两阶段设计：
 *   阶段一（RCU 内，只做不睡眠的事）：for_each_process 只遍历线程组 leader，
 *     按 comm 前缀（处理 15 字符截断）预筛出候选并 get_task_struct 留引用；
 *   阶段二（允许睡眠）：对候选 present-only 读取 argv[0]（htfg_cmdline_is；
 *     不换入；argv 页被换出时视为不命中）做整串比对；
 *   候选全灭 → 兜底：全量收集 pid 再逐个验证（comm 被改的进程也能找到）。
 * 命中则写 kop->pid；找不到 → -ESRCH。
 */
static void htfg_op_find_pid(struct htfg_op *kop)
{
	char name[HTFG_FIND_LEN_MAX + 1];
	struct task_struct *cand[HTFG_FIND_CAND_MAX];
	struct task_struct *p;
	unsigned int ncand = 0;
	unsigned int namelen;
	unsigned int npids;
	unsigned int i;
	u32 *pids;

	if (kop->len < 2 || kop->len > HTFG_FIND_LEN_MAX) {
		kop->out = (uint32_t)-EINVAL;
		return;
	}
	if (copy_from_user(name, (void __user *)(uintptr_t)kop->buf,
			   kop->len)) {
		kop->out = (uint32_t)-EFAULT;
		return;
	}
	if (name[kop->len - 1] != '\0') {
		kop->out = (uint32_t)-EINVAL;
		return;
	}
	namelen = kop->len - 1;

	rcu_read_lock();
	for_each_process(p) {
		size_t clen;

		if (p->flags & PF_KTHREAD)
			continue;
		if (!p->mm)
			continue;
		clen = strnlen(p->comm, TASK_COMM_LEN - 1);
		if (clen > namelen)
			continue;
		if (strncmp(p->comm, name, clen) != 0)
			continue;
		if (ncand < HTFG_FIND_CAND_MAX) {
			get_task_struct(p);
			cand[ncand++] = p;
		}
	}
	rcu_read_unlock();

	for (i = 0; i < ncand; i++) {
		if (htfg_cmdline_is(cand[i], name, namelen)) {
			kop->pid = (uint32_t)task_pid_nr(cand[i]);
			kop->out = 0;
			goto out_put_cand;
		}
	}

	/* 兜底：全量扫描 */
	pids = kmalloc_array(HTFG_FIND_PID_MAX, sizeof(*pids), GFP_KERNEL);
	if (!pids) {
		kop->out = (uint32_t)-ENOMEM;
		goto out_put_cand;
	}
	npids = 0;
	rcu_read_lock();
	for_each_process(p) {
		if (p->flags & PF_KTHREAD)
			continue;
		if (!p->mm)
			continue;
		if (npids >= HTFG_FIND_PID_MAX)
			break;
		pids[npids++] = (u32)task_pid_nr(p);
	}
	rcu_read_unlock();

	for (i = 0; i < npids; i++) {
		p = find_get_task_by_vpid((pid_t)pids[i]);
		if (!p)
			continue;
		if (htfg_cmdline_is(p, name, namelen)) {
			kop->pid = pids[i];
			kop->out = 0;
			put_task_struct(p);
			kfree(pids);
			goto out_put_cand;
		}
		put_task_struct(p);
	}
	kfree(pids);
	kop->out = (uint32_t)-ESRCH;

out_put_cand:
	for (i = 0; i < ncand; i++)
		put_task_struct(cand[i]);
}

/* ============================================================ GET_VMAS */

/* 从 d_path 结果取 basename；顺手去掉 " (deleted)" 后缀（memfd 等常见） */
static void htfg_basename_into(char *dst, size_t dstlen, const char *path)
{
	const char *base;
	size_t n;

	base = strrchr(path, '/');
	base = base ? base + 1 : path;
	n = strlen(base);
	if (n > 10 && strcmp(base + n - 10, " (deleted)") == 0)
		n -= 10;
	if (n > dstlen - 1)
		n = dstlen - 1;
	memcpy(dst, base, n);
	dst[n] = '\0';
}

/*
 * 读匿名名（[anon:xxx] 里的 xxx）。调用时必须持有 mm 的 mmap 读锁。
 *
 * present-only：follow_page 只读已驻留页 → kmap → 拷页内 → put_page；
 * 绝不缺页/换入（GUP 已移除）。读不到不报错（名字留空，尽力而为）。
 *
 * 注意：本 5.10 树的 vma->anon_name 是"老式 Android backport"形态——
 * const char __user *（目标进程地址空间里的用户指针），且没有
 * CONFIG_ANON_VMA_NAME 这个配置项。这里刻意不做任何 #ifdef 判断：
 * 将来换内核（6.1+ 变成 struct anon_vma_name *）时让它编译报错再适配，
 * 宁可编译红，不可静默降级。
 */
static void htfg_read_anon_name(struct mm_struct *mm, const char __user *up,
				char *dst, size_t dstlen)
{
	unsigned long vaddr;
	unsigned long page_off;
	size_t done = 0;

	if (!up)
		return;
	vaddr = (unsigned long)up;
	page_off = vaddr & ~PAGE_MASK;

	while (done < dstlen - 1) {
		struct page *page;
		const char *kaddr;
		const char *src;
		size_t want;
		size_t n;

		want = dstlen - 1 - done;
		if (want > PAGE_SIZE - page_off)
			want = PAGE_SIZE - page_off;

		page = htfg_get_present_page(mm, vaddr);
		if (!page)
			break;

		kaddr = kmap(page);
		src = kaddr + htfg_page_off(page, vaddr);
		n = strnlen(src, want);
		memcpy(dst + done, src, n);
		kunmap(page);
		put_page(page);

		done += n;
		if (n < want)
			break;			/* 遇到 NUL：名字读完 */
		vaddr += PAGE_SIZE - page_off;	/* 名字跨页：继续下一页 */
		page_off = 0;
	}
	dst[done] = '\0';
}

/* 把一个 vma 的字段填进条目（调用时持 mm 的 mmap 读锁） */
static void htfg_fill_vma(struct mm_struct *mm, struct vm_area_struct *vma,
			  struct htfg_vma *e)
{
	char path[256];
	char *pbuf;
	u32 kind = HTFG_VMA_KIND_ANON;

	memset(e, 0, sizeof(*e));
	e->start = vma->vm_start;
	e->end = vma->vm_end;
	e->flags = (uint64_t)vma->vm_flags;
	e->pgoff = (uint64_t)vma->vm_pgoff << PAGE_SHIFT;

	if (vma->vm_flags & VM_READ)
		e->prot |= HTFG_VMA_READ;
	if (vma->vm_flags & VM_WRITE)
		e->prot |= HTFG_VMA_WRITE;
	if (vma->vm_flags & VM_EXEC)
		e->prot |= HTFG_VMA_EXEC;
	/*
	 * 第 4 位与 /proc/maps 同口径：本树 fs/proc/task_mmu.c:313 用的是
	 * VM_MAYSHARE 而不是 VM_SHARED（seq_putc(m, flags & VM_MAYSHARE ?
	 * 's' : 'p')）。两者在"只读共享文件映射"上分离——例如
	 * /dev/__properties__/*（smaps VmFlags="rd mr me ms"、无 sh）——
	 * 用 VM_SHARED 会漏报 's'（实测 S8 的 14 条差异全部由此而来）。
	 */
	if (vma->vm_flags & VM_MAYSHARE)
		e->prot |= HTFG_VMA_SHARED;

	if (vma->vm_file) {
		kind = HTFG_VMA_KIND_FILE;
		pbuf = file_path(vma->vm_file, path, sizeof(path));
		if (!IS_ERR(pbuf))
			htfg_basename_into(e->name, sizeof(e->name), pbuf);
	} else {
		const char __user *an = vma_get_anon_name(vma);

		/*
		 * 与 procfs 的 seq_print_vma_name() 同口径：vma_get_anon_name()
		 * 只对无 vm_file 的 VMA 返回 anon_name 字段（本树 backport 中该
		 * 字段与 shared.rb 同 union，但 rb 仅用于"文件映射进 i_mmap 树"，
		 * 匿名时字段要么 NULL、要么是有效用户指针；procfs 同样无条件
		 * 使用，不做任何附加判断）。
		 */
		if (an) {
			htfg_read_anon_name(mm, an, e->name,
					    sizeof(e->name));
			if (e->name[0] != '\0')
				kind = HTFG_VMA_KIND_ANON_NAMED;
		}
	}
	e->kind = kind;
}

/*
 * 枚举目标进程的全部 VMA。
 *
 * 分批（每批一页内核缓冲）的原因（本步最容易踩的死锁坑）：
 *   自读场景（pid 就是调用者自己）下，持着目标 mm 的读锁给用户拷数据，
 *   用户页缺页会递归请求同一把 mmap 读锁——有写者排队即死锁。
 *   所以照 procfs maps 的模式：锁内只填内核缓冲，锁外才 copy_to_user。
 *
 * 语义：count = 已交付条目数；容量不足 → out=-ENOSPC（可扩容重试）；
 *       每批之间会短暂放锁，期间目标若改映射，快照可能不一致（文档已声明）。
 */
static void htfg_op_get_vmas(struct htfg_op *kop)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct htfg_vma *batch;
	unsigned long cursor = 0;
	unsigned int capacity;
	unsigned int written = 0;

	capacity = kop->len / HTFG_VMA_SIZE;
	if (capacity == 0) {
		kop->count = 0;
		kop->out = (uint32_t)-ENOSPC;
		return;
	}

	task = find_get_task_by_vpid(kop->pid);
	if (!task) {
		kop->out = (uint32_t)-ESRCH;
		return;
	}
	mm = get_task_mm(task);
	if (!mm) {
		kop->out = (uint32_t)-ESRCH;
		goto out_put_task;
	}

	batch = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!batch) {
		kop->out = (uint32_t)-ENOMEM;
		goto out_mmput;
	}

	for (;;) {
		struct vm_area_struct *vma;
		unsigned int room;
		unsigned int limit;
		unsigned int n;

		room = capacity - written;
		if (room == 0) {
			bool more;

			/* 容量已满：再探一次还有没有 VMA——有则 ENOSPC，没有则正好收尾 */
			mmap_read_lock(mm);
			vma = find_vma(mm, cursor);
			more = vma != NULL;
			mmap_read_unlock(mm);
			kop->out = more ? (uint32_t)-ENOSPC : 0;
			break;
		}

		limit = min(room, (unsigned int)HTFG_VMA_BATCH_MAX);
		n = 0;
		mmap_read_lock(mm);
		while (n < limit) {
			vma = find_vma(mm, cursor);
			if (!vma)
				break;
			htfg_fill_vma(mm, vma, &batch[n]);
			cursor = vma->vm_end;
			n++;
		}
		mmap_read_unlock(mm);

		if (n == 0) {		/* 没有更多 VMA */
			kop->out = 0;
			break;
		}
		if (copy_to_user((void __user *)(uintptr_t)
				 (kop->buf + (uint64_t)written * HTFG_VMA_SIZE),
				 batch, n * HTFG_VMA_SIZE)) {
			kop->out = (uint32_t)-EFAULT;
			break;
		}
		written += n;
	}
	kfree(batch);
	kop->count = written;

out_mmput:
	mmput(mm);
out_put_task:
	put_task_struct(task);
}

/* ============================================================ TOUCH */

/*
 * 第 5 步（2026-10-12）：触摸屏查询与事件注入。
 *
 * 机制：把用户态构造的事件三元组直接交给真实触摸屏 input_dev 的
 * input_event()——与"App 直写 /dev/input/eventN"（evdev_write →
 * input_inject_event）在输入核心处同一路径；事件源设备、时间戳（投递时刻
 * CLOCK_MONOTONIC）、框架解析完全一致。
 *
 * 隐蔽性纪律（与全文件口径一致，另加三条本段专属）：
 *   - 不注册 input_handler —— /proc/bus/input/handlers（内核默认 0444）保持
 *     零新增行；不新建 input_dev、不建 proc/sysfs 条目；
 *   - 不缓存设备指针 —— 触摸固件重载会 unregister/re-register，裸指针必
 *     UAF；每次调用现场查找，命中设备在遍历回调内 get_device 保引用、用完
 *     put_device。input_dev（含 absinfo/mt）内存的唯一释放点是
 *     input_dev_release()（被引用计数保护），故"持引用期间注入"在热插拔/
 *     固件重载下无 UAF；
 *   - 零 printk；结构性/值域错误一律整批 -EINVAL 零注入（fail-closed）。
 */

/* 设备遍历：统计"触摸屏"命中总数，并把第 want 个（0 基）留引用带出 */
struct htfg_touch_scan {
	unsigned int want;	/* 想要的命中序号（0 基） */
	unsigned int matches;	/* 已见命中数（遍历完 = 命中总数） */
	unsigned int pick_index;	/* 命中设备的序号 */
	struct input_dev *pick;	/* 命中设备（回调内 get_device 保引用） */
};

/*
 * 触摸屏判据（沿用触控项目模块的"三特征"启发式，另要求 dev->mt 非空）：
 *   EV_ABS ∧ ABS_MT_SLOT ∧ ABS_MT_POSITION_X ∧ ABS_MT_POSITION_Y。
 * 遍历不提前终止（要统计命中总数）；序号命中时 get_device 留存引用。
 */
static int htfg_touch_scan_cb(struct device *d, void *data)
{
	struct htfg_touch_scan *sc = data;
	struct input_dev *idev = to_input_dev(d);

	if (!test_bit(EV_ABS, idev->evbit) ||
	    !test_bit(ABS_MT_SLOT, idev->absbit) ||
	    !test_bit(ABS_MT_POSITION_X, idev->absbit) ||
	    !test_bit(ABS_MT_POSITION_Y, idev->absbit) ||
	    !idev->mt)
		return 0;

	if (sc->matches == sc->want) {
		get_device(d);
		sc->pick = idev;
		sc->pick_index = sc->matches;
	}
	sc->matches++;
	return 0;
}

/* 找第 want 个触摸屏；返回持引用的 input_dev（调用方负责 put_device），
 * 找不到返回 NULL。total/got 为可选出参（命中总数 / 实际命中序号）。 */
static struct input_dev *htfg_touch_find(unsigned int want,
					 unsigned int *total,
					 unsigned int *got)
{
	struct htfg_touch_scan sc;

	memset(&sc, 0, sizeof(sc));
	sc.want = want;

	class_for_each_device(&input_class, NULL, &sc, htfg_touch_scan_cb);

	if (total)
		*total = sc.matches;
	if (got)
		*got = sc.pick_index;
	return sc.pick;
}

/* 填一个轴的 absinfo 范围（设备未声明该码 → 全 0） */
static void htfg_touch_fill_axis(const struct input_dev *idev,
				 unsigned int code, int32_t *min, int32_t *max)
{
	if (test_bit(code, idev->absbit) && idev->absinfo) {
		*min = idev->absinfo[code].minimum;
		*max = idev->absinfo[code].maximum;
	} else {
		*min = 0;
		*max = 0;
	}
}

/* 设备支持码位图（HTFG_TOUCH_CAP_*） */
static uint32_t htfg_touch_caps(const struct input_dev *idev)
{
	uint32_t caps = 0;

	if (test_bit(ABS_MT_SLOT, idev->absbit))
		caps |= HTFG_TOUCH_CAP_MT_SLOT;
	if (test_bit(ABS_MT_TRACKING_ID, idev->absbit))
		caps |= HTFG_TOUCH_CAP_MT_TRACKING_ID;
	if (test_bit(ABS_MT_POSITION_X, idev->absbit))
		caps |= HTFG_TOUCH_CAP_MT_POSITION_X;
	if (test_bit(ABS_MT_POSITION_Y, idev->absbit))
		caps |= HTFG_TOUCH_CAP_MT_POSITION_Y;
	if (test_bit(ABS_MT_TOUCH_MAJOR, idev->absbit))
		caps |= HTFG_TOUCH_CAP_MT_TOUCH_MAJOR;
	if (test_bit(ABS_MT_TOUCH_MINOR, idev->absbit))
		caps |= HTFG_TOUCH_CAP_MT_TOUCH_MINOR;
	if (test_bit(ABS_MT_PRESSURE, idev->absbit))
		caps |= HTFG_TOUCH_CAP_MT_PRESSURE;
	if (test_bit(BTN_TOUCH, idev->keybit))
		caps |= HTFG_TOUCH_CAP_BTN_TOUCH;
	if (test_bit(BTN_TOOL_FINGER, idev->keybit))
		caps |= HTFG_TOUCH_CAP_BTN_TOOL_FINGER;
	return caps;
}

/* TOUCH_DEV：查询触摸屏信息（语义详见 htfg.h 的 struct htfg_touch_info 注释） */
static void htfg_op_touch_dev(struct htfg_op *kop)
{
	struct htfg_touch_info info;
	struct input_dev *idev;
	unsigned int total = 0;
	unsigned int index = 0;

	if (!kop->buf || kop->len < HTFG_TOUCH_INFO_SIZE) {
		kop->count = 0;
		kop->out = (uint32_t)-ENOSPC;
		return;
	}

	idev = htfg_touch_find(kop->pid, &total, &index);
	if (!idev) {
		kop->count = 0;
		kop->out = (uint32_t)-ENODEV;
		return;
	}

	/* ABI 自检：先读调用方填的 size（不符 = 用户态头文件版本不一致） */
	memset(&info, 0, sizeof(info));
	if (copy_from_user(&info.size, (void __user *)(uintptr_t)kop->buf,
			   sizeof(info.size))) {
		kop->out = (uint32_t)-EFAULT;
		goto out_put;
	}
	if (info.size != HTFG_TOUCH_INFO_SIZE) {
		kop->out = (uint32_t)-EINVAL;
		goto out_put;
	}

	info.size = HTFG_TOUCH_INFO_SIZE;
	strscpy(info.name, idev->name ? idev->name : "", sizeof(info.name));
	htfg_touch_fill_axis(idev, ABS_MT_POSITION_X,
			     &info.x_min, &info.x_max);
	htfg_touch_fill_axis(idev, ABS_MT_POSITION_Y,
			     &info.y_min, &info.y_max);
	htfg_touch_fill_axis(idev, ABS_MT_TOUCH_MAJOR,
			     &info.major_min, &info.major_max);
	htfg_touch_fill_axis(idev, ABS_MT_TOUCH_MINOR,
			     &info.minor_min, &info.minor_max);
	htfg_touch_fill_axis(idev, ABS_MT_PRESSURE,
			     &info.pressure_min, &info.pressure_max);
	info.num_slots = (uint32_t)idev->mt->num_slots;
	info.mt_flags = idev->mt->flags;
	info.caps = htfg_touch_caps(idev);
	info.dev_index = index;
	info.dev_matches = total;
	strscpy(info.sysfs_name, dev_name(&idev->dev),
		sizeof(info.sysfs_name));

	if (copy_to_user((void __user *)(uintptr_t)kop->buf, &info,
			 sizeof(info))) {
		kop->out = (uint32_t)-EFAULT;
		goto out_put;
	}
	kop->pid = index;	/* 出：实际命中序号 */
	kop->count = total;
	kop->out = 0;

out_put:
	put_device(&idev->dev);
}

/* 单事件校验结果 */
#define HTFG_TOUCH_EV_OK	0	/* 可注入 */
#define HTFG_TOUCH_EV_SKIP	1	/* 白名单码但设备不支持：跳过（count 少计） */
#define HTFG_TOUCH_EV_BAD	2	/* 结构性/值域错误：整批拒绝 */

/*
 * 单事件校验（无副作用，可重复调用；SEND 先全量校验、后注入）。
 * 与输入核心行为对齐的关键：不支持的码在核心处被静默丢弃
 * （input_get_disposition → INPUT_IGNORE_EVENT），不报错——所以除"核心
 * 四码"（SLOT/TRACKING_ID/X/Y，真·配置错误）外，白名单码不支持时跳过。
 */
static int htfg_touch_ev_check(const struct input_dev *idev,
			       const struct htfg_touch_ev *ev)
{
	const struct input_absinfo *ab;
	int32_t v = ev->value;

	if (ev->type == EV_SYN) {
		if (ev->code != SYN_REPORT || v != 0)
			return HTFG_TOUCH_EV_BAD;
		return HTFG_TOUCH_EV_OK;
	}

	if (ev->type == EV_KEY) {
		if (ev->code != BTN_TOUCH && ev->code != BTN_TOOL_FINGER)
			return HTFG_TOUCH_EV_BAD;
		if (v != 0 && v != 1)
			return HTFG_TOUCH_EV_BAD;
		if (!test_bit(ev->code, idev->keybit))
			return HTFG_TOUCH_EV_SKIP;
		return HTFG_TOUCH_EV_OK;
	}

	if (ev->type != EV_ABS)
		return HTFG_TOUCH_EV_BAD;

	switch (ev->code) {
	case ABS_MT_SLOT:
		if (!test_bit(ABS_MT_SLOT, idev->absbit))
			return HTFG_TOUCH_EV_BAD;
		if (v < 0 || (uint32_t)v >= (uint32_t)idev->mt->num_slots)
			return HTFG_TOUCH_EV_BAD;
		return HTFG_TOUCH_EV_OK;
	case ABS_MT_TRACKING_ID:
		if (!test_bit(ABS_MT_TRACKING_ID, idev->absbit))
			return HTFG_TOUCH_EV_BAD;
		if (v < -1)
			return HTFG_TOUCH_EV_BAD;
		return HTFG_TOUCH_EV_OK;
	case ABS_MT_TOUCH_MAJOR:
	case ABS_MT_TOUCH_MINOR:
	case ABS_MT_PRESSURE:
		if (!test_bit(ev->code, idev->absbit))
			return HTFG_TOUCH_EV_SKIP;
		break;
	case ABS_MT_POSITION_X:
	case ABS_MT_POSITION_Y:
		if (!test_bit(ev->code, idev->absbit))
			return HTFG_TOUCH_EV_BAD;
		break;
	default:
		return HTFG_TOUCH_EV_BAD;
	}

	/* 值域按 absinfo（退化区间 minimum==maximum 视为"未声明"跳过） */
	if (idev->absinfo) {
		ab = &idev->absinfo[ev->code];
		if (ab->minimum != ab->maximum &&
		    (v < ab->minimum || v > ab->maximum))
			return HTFG_TOUCH_EV_BAD;
	}
	return HTFG_TOUCH_EV_OK;
}

/*
 * TOUCH_SEND：注入一帧事件（语义详见 htfg.h 的 struct htfg_touch_ev 注释）。
 * 先全量校验（错误 = 零注入），再逐条 input_event()——input_event 内部只有
 * dev->event_lock（spinlock、关 IRQ）一把锁、无睡眠点，prctl 进程上下文安全；
 * copy_from_user 在进入任何锁之前完成。
 */
static void htfg_op_touch_send(struct htfg_op *kop)
{
	struct htfg_touch_ev evs[HTFG_TOUCH_EV_MAX];
	uint8_t verdict[HTFG_TOUCH_EV_MAX];
	struct input_dev *idev;
	unsigned int n;
	unsigned int i;
	unsigned int sent = 0;

	if (!kop->buf || kop->len == 0 || kop->len % HTFG_TOUCH_EV_SIZE ||
	    kop->len > (uint32_t)(HTFG_TOUCH_EV_MAX * HTFG_TOUCH_EV_SIZE)) {
		kop->out = (uint32_t)-EINVAL;
		return;
	}
	n = kop->len / HTFG_TOUCH_EV_SIZE;

	if (copy_from_user(evs, (void __user *)(uintptr_t)kop->buf,
			   kop->len)) {
		kop->out = (uint32_t)-EFAULT;
		return;
	}

	idev = htfg_touch_find(kop->pid, NULL, NULL);
	if (!idev) {
		kop->out = (uint32_t)-ENODEV;
		return;
	}

	/* 被他人 grab 的设备：注入会被输入核心整条丢弃，先明确报错 */
	if (READ_ONCE(idev->grab)) {
		kop->out = (uint32_t)-EBUSY;
		goto out_put;
	}

	for (i = 0; i < n; i++) {
		verdict[i] = (uint8_t)htfg_touch_ev_check(idev, &evs[i]);
		if (verdict[i] == HTFG_TOUCH_EV_BAD) {
			kop->out = (uint32_t)-EINVAL;
			goto out_put;
		}
	}

	for (i = 0; i < n; i++) {
		if (verdict[i] == HTFG_TOUCH_EV_SKIP)
			continue;
		input_event(idev, evs[i].type, evs[i].code, evs[i].value);
		sent++;
	}

	kop->count = sent;
	kop->out = 0;

out_put:
	put_device(&idev->dev);
}

/* ============================================== SIGN 身份：签名证书指纹固定
 * （certificate pinning；不验签名记录/内容摘要，见文件头 2026-10-06 说明） */

/*
 * 正式身份判据（2026-10-06 M2.3 变更，替代"把正式 App 的 uid 写死进白名单"；
 * uid 判据跨设备/重装都要改代码重刷，证书指纹判据零维护）。
 * 口径：只固定 v2 签名块首张证书的 SHA-256（pinning），信任 PackageManager
 * 安装时已做完整验签、且 /data/app 下 APK 对普通 App 不可变。
 *
 * 机制（KernelSU / KernelSU-Next / SukiSU-Ultra / ReSukiSU 同款思路的等价精简版）：
 *   调用者 uid →（借 system_server 凭据）读 /data/system/packages.list 得其包名
 *   → 扫 /data/app 找到该包已安装的 base.apk → 解析 ZIP 的 "APK Sig Block 42"
 *   v2 签名块、取签名者证书 → SHA-256(证书) == 内置 htai 指纹。全部通过则把
 *   该 uid 写入验证缓存（TTL），之后调用只多一次表查询。
 *
 * 不限定包名（2026-10-06 指示）：判据只认证书指纹——同一把 htai 密钥签名的
 * 任意已安装 App 均可通过（一钥多 App）。包名仅用于"按 uid 找到该 App 的
 * 安装副本"，不参与放行判定。
 *
 * 为什么不可伪造（威胁模型 = 设备上无 root 的其他 App）：
 *   - 信任链自内核可信的 uid 出发，途经 packages.list 与 /data/app（均为系统
 *     属主数据，调用者无写权限）；证书匹配需要 htai 私钥。调用者自报的任何
 *     东西（进程名/argv/参数）都不参与判定；
 *   - 指纹是编译期常量：换签名密钥才需要重编内核（罕见）；重装/换机/uid 变化
 *     零维护。
 *
 * 可检测性纪律（与全文件口径一致）：
 *   - 零 printk，一切失败静默拒绝（fail-closed）；
 *   - 文件一律 __FMODE_NONOTIFY + O_NOATIME 打开（不产生 fsnotify 事件、不落
 *     atime）；读取借用 system_server 凭据（comm+uid 双匹配，其他 App 无法
 *     满足）；不新增 hook、不新增定时器；
 *   - 冷路径只发生在"本 App 冷启动首调 / TTL 过期"，~ms 级、每 TTL 至多一次。
 *
 * 参考实现：KernelSU 系 kernel/manager/apk_sign.c、throne_tracker.c（GPL-2.0）。
 */

/* 以内核特权方式打开只读文件；flags 额外叠加 __FMODE_NONOTIFY（不产生
 * fsnotify 事件）。调用者对返回的 file 自行 filp_close。 */
static struct file *htfg_kopen(const char *path, int flags,
			       const struct cred *cred)
{
	struct path p;
	int ret;

	ret = kern_path(path, LOOKUP_FOLLOW, &p);
	if (ret)
		return ERR_PTR(ret);
	return dentry_open(&p, flags | __FMODE_NONOTIFY, cred);
}

/* 从 pos 起精确读 len 字节（不越 end 界），成功推进 pos */
static bool htfg_read_exact(struct file *fp, void *buf, size_t len,
			    loff_t *pos, loff_t end)
{
	if (*pos < 0 || *pos > end || (loff_t)len > end - *pos)
		return false;
	return kernel_read(fp, buf, len, pos) == (ssize_t)len;
}

/* 读 4 字节长度前缀并求出其值区间的结束位置（AOSP 签名块解析同款） */
static bool htfg_read_lp(struct file *fp, loff_t *pos, loff_t container_end,
			 loff_t *value_end)
{
	u32 length;

	if (!htfg_read_exact(fp, &length, sizeof(length), pos, container_end))
		return false;
	if (length > INT_MAX || length > (u64)(container_end - *pos))
		return false;
	*value_end = *pos + length;
	return true;
}

/* 一次性 SHA-256（校验每 TTL 至多一次，不做 tfm 常驻） */
struct htfg_sdesc {
	struct shash_desc shash;
	char ctx[];
};

static int htfg_sha256(const u8 *data, unsigned int datalen, u8 *digest)
{
	struct crypto_shash *alg;
	struct htfg_sdesc *sdesc;
	int size;
	int ret;

	alg = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(alg))
		return PTR_ERR(alg);

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kzalloc(size, GFP_KERNEL);
	if (!sdesc) {
		crypto_free_shash(alg);
		return -ENOMEM;
	}
	sdesc->shash.tfm = alg;
	ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
	kfree(sdesc);
	crypto_free_shash(alg);
	return ret;
}

/*
 * v2 签名块内层：signers 序列 → 第一个 signer → signed data → digests →
 * certificates 序列 → 第一个证书。取证书 SHA-256 与内置指纹（大小+哈希）
 * 双匹配。任何结构异常都是 false。
 */
static bool htfg_apk_check_block(struct file *fp, loff_t *pos, loff_t block_end)
{
	loff_t signers_end;
	loff_t signer_end;
	loff_t signed_data_end;
	loff_t digests_end;
	loff_t certificates_end;
	u32 certificate_size;
	char cert[HTFG_SIGN_CERT_MAX];
	unsigned char digest[SHA256_DIGEST_SIZE];
	char hash_str[SHA256_DIGEST_SIZE * 2 + 1];

	if (!htfg_read_lp(fp, pos, block_end, &signers_end) ||
	    !htfg_read_lp(fp, pos, signers_end, &signer_end) ||
	    !htfg_read_lp(fp, pos, signer_end, &signed_data_end) ||
	    !htfg_read_lp(fp, pos, signed_data_end, &digests_end))
		return false;

	/* digests 之后进入 signed data 的第二段：certificates 序列 */
	*pos = digests_end;
	if (!htfg_read_lp(fp, pos, signed_data_end, &certificates_end))
		return false;
	if (!htfg_read_exact(fp, &certificate_size, sizeof(certificate_size),
			     pos, certificates_end))
		return false;
	if (certificate_size > HTFG_SIGN_CERT_MAX ||
	    certificate_size > (u64)(certificates_end - *pos))
		return false;
	if (!htfg_read_exact(fp, cert, certificate_size, pos, certificates_end))
		return false;

	if (htfg_sha256((const u8 *)cert, certificate_size, digest))
		return false;
	hash_str[SHA256_DIGEST_SIZE * 2] = '\0';
	bin2hex(hash_str, digest, SHA256_DIGEST_SIZE);

	return certificate_size == HTFG_SIGN_CERT_SIZE &&
	       strcmp(hash_str, HTFG_SIGN_CERT_SHA256) == 0;
}

/* ZIP 本地文件头（30 字节，v1 检查用） */
struct htfg_zip_entry_header {
	u32 signature;
	u16 version;
	u16 flags;
	u16 compression;
	u16 mod_time;
	u16 mod_date;
	u32 crc32;
	u32 compressed_size;
	u32 uncompressed_size;
	u16 file_name_length;
	u16 extra_field_length;
} __packed;

/*
 * v1 检查（与参考实现同款加固）：存在 META-INF/MANIFEST.MF 说明该 APK 同时
 * 带 v1 签名——正式版签成"纯 v2"（apksigner 关 v1），见到 v1 一律视为异常。
 * 只扫本地文件头（不依赖 central directory），上限 HTFG_SIGN_ENTRY_MAX 条。
 */
static bool htfg_apk_has_v1(struct file *fp)
{
	static const char manifest[] = "META-INF/MANIFEST.MF";
	struct htfg_zip_entry_header h;
	loff_t pos = 0;
	int i;

	for (i = 0; i < HTFG_SIGN_ENTRY_MAX; i++) {
		char name[sizeof(manifest)];

		if (kernel_read(fp, &h, sizeof(h), &pos) != (ssize_t)sizeof(h))
			return false;
		if (h.signature != 0x04034b50u)	/* "PK\x03\x04" */
			return false;
		if (h.file_name_length == sizeof(manifest) - 1) {
			if (kernel_read(fp, name, h.file_name_length, &pos) !=
			    (ssize_t)h.file_name_length)
				return false;
			name[h.file_name_length] = '\0';
			if (strcmp(name, manifest) == 0)
				return true;
		} else {
			pos += h.file_name_length;
		}
		pos += h.extra_field_length + h.compressed_size;
	}
	return false;
}

/*
 * 完整校验一个 APK（只读；打开失败/任何结构异常/指纹不符 → false）：
 *   尾部找 EOCD → 中央目录前定位 "APK Sig Block 42" → 遍历 ID-value 对
 *   （只允许 v2=0x7109871a 与 APK verity padding=0x42726577，其余即异常；
 *   恰好一个 v2 块）→ v2 证书指纹双匹配 → 不得存在 v1 签名。
 */
static bool htfg_apk_check_signature(const char *path, const struct cred *cred)
{
	unsigned char buf[16];
	struct file *fp;
	loff_t file_size;
	loff_t pos;
	loff_t pairs_end;
	u32 cd_offset;
	u64 block_size;
	u64 block_size_at_head;
	int v2_blocks = 0;
	u32 pairs = 0;
	bool v2_valid = false;
	int i;

	fp = htfg_kopen(path, O_RDONLY | O_NOATIME, cred);
	if (IS_ERR(fp))
		return false;

	file_size = generic_file_llseek(fp, 0, SEEK_END);
	if (file_size < 0)
		goto out;

	/* 从文件尾回扫 EOCD（comment 长度未知，最多 0xffff 次） */
	for (i = 0; ; i++) {
		unsigned short comment_size;
		u32 magic;

		if (i > 0xffff)
			goto out;
		pos = file_size - i - 2;
		if (!htfg_read_exact(fp, &comment_size, sizeof(comment_size),
				     &pos, file_size))
			goto out;
		if (comment_size != i)
			continue;
		pos -= 22;			/* 回到 EOCD 起点 */
		if (!htfg_read_exact(fp, &magic, sizeof(magic), &pos, file_size))
			goto out;
		if (magic == 0x06054b50u)	/* "PK\x05\x06" */
			break;
	}

	/* pos 现位于 EOCD+4；再跳 12 字节到"中央目录偏移"字段 */
	pos += 12;
	if (!htfg_read_exact(fp, &cd_offset, sizeof(cd_offset), &pos, file_size))
		goto out;
	if (cd_offset < 0x20)
		goto out;

	/* 签名块：位于中央目录之前；尾部 16 字节魔数 + 8 字节块大小 */
	pairs_end = (loff_t)cd_offset - 0x18;
	pos = pairs_end;
	if (!htfg_read_exact(fp, &block_size, sizeof(block_size), &pos, cd_offset))
		goto out;
	if (!htfg_read_exact(fp, buf, sizeof(buf), &pos, cd_offset))
		goto out;
	if (memcmp(buf, "APK Sig Block 42", sizeof(buf)) != 0)
		goto out;
	if (block_size < 0x18 || block_size > INT_MAX - 0x8 ||
	    block_size > (u64)cd_offset - 0x8)
		goto out;
	/* 块头部的 size 必须与尾部一致（AOSP 解析器同款校验） */
	pos = (loff_t)cd_offset - (loff_t)block_size - 0x8;
	if (!htfg_read_exact(fp, &block_size_at_head,
			     sizeof(block_size_at_head), &pos, pairs_end))
		goto out;
	if (block_size_at_head != block_size)
		goto out;

	/* 遍历 ID-value 对（上限见 HTFG_SIGN_PAIR_MAX；超出即判异常） */
	while (pos < pairs_end) {
		u64 pair_len;
		loff_t pair_end;
		u32 id;

		if (++pairs > HTFG_SIGN_PAIR_MAX)
			goto invalid;	/* 病态签名块：按异常失败（fail-closed） */
		if (!htfg_read_exact(fp, &pair_len, sizeof(pair_len),
				     &pos, pairs_end))
			goto out;
		if (pair_len < sizeof(id) || pair_len > INT_MAX ||
		    pair_len > (u64)(pairs_end - pos))
			goto out;
		pair_end = pos + (loff_t)pair_len;
		if (!htfg_read_exact(fp, &id, sizeof(id), &pos, pair_end))
			goto out;
		if (id == 0x7109871au) {	/* APK Signature Scheme v2 */
			v2_blocks++;
			v2_valid = htfg_apk_check_block(fp, &pos, pair_end);
		} else if (id != 0x42726577u) {	/* APK verity padding */
			goto invalid;
		}
		pos = pair_end;
	}

	if (v2_blocks != 1)
		v2_valid = false;
	if (v2_valid && htfg_apk_has_v1(fp))
		v2_valid = false;
	goto out;

invalid:
	v2_valid = false;
out:
	filp_close(fp, NULL);
	return v2_valid;
}

/* packages.list 一行的前两个字段："包名 uid"（其余字段忽略） */
static bool htfg_pl_line_match(const char *line, u32 want_uid, char *pkg_out)
{
	char name[HTFG_PKG_MAX];
	size_t i = 0;
	size_t n = 0;
	u32 uid = 0;
	bool digit = false;

	while (line[n] != '\0' && line[n] != ' ' && line[n] != '\t') {
		if (i < sizeof(name) - 1)
			name[i++] = line[n];
		n++;
	}
	name[i] = '\0';
	if (i == 0)
		return false;

	while (line[n] == ' ' || line[n] == '\t')
		n++;

	while (line[n] >= '0' && line[n] <= '9') {
		uid = uid * 10 + (u32)(line[n] - '0');
		digit = true;
		n++;
	}
	if (!digit || uid != want_uid)
		return false;
	if (line[n] != '\0' && line[n] != ' ' && line[n] != '\t')
		return false;		/* uid 字段后必须是分隔符/行尾 */

	strscpy(pkg_out, name, HTFG_PKG_MAX);
	return true;
}

/* 在 packages.list 全文里找 uid 对应的包名（逐块读 + 行装配；超长行丢弃） */
static bool htfg_pkg_by_uid(struct file *fp, u32 want_uid, char *pkg_out)
{
	char chunk[1024];
	char line[512];
	size_t ll = 0;
	bool overflow = false;
	loff_t pos = 0;

	for (;;) {
		ssize_t n;
		ssize_t i;

		n = kernel_read(fp, chunk, sizeof(chunk), &pos);
		if (n <= 0)
			break;
		if (pos > HTFG_PL_READ_MAX)
			return false;	/* 尺寸异常：拒绝 */
		for (i = 0; i < n; i++) {
			char c = chunk[i];

			if (c == '\n') {
				if (!overflow && ll > 0) {
					line[ll] = '\0';
					if (htfg_pl_line_match(line, want_uid,
							       pkg_out))
						return true;
				}
				ll = 0;
				overflow = false;
			} else if (!overflow) {
				if (ll < sizeof(line) - 1)
					line[ll++] = c;
				else
					overflow = true;
			}
		}
	}
	if (!overflow && ll > 0) {	/* 末行无换行符 */
		line[ll] = '\0';
		if (htfg_pl_line_match(line, want_uid, pkg_out))
			return true;
	}
	return false;
}

/* readdir 回调：在 /data/app 里找 `<pkg>-<随机>` 目录（顶层顺带收集 ~~* 哈希
 * 子目录）。pkg = 目标包名（来自 packages.list，按调用者 uid 查得，任意包名）。 */
struct htfg_apk_scan {
	struct dir_context ctx;
	const char *parent;		/* 当前被遍历目录的完整路径 */
	bool want_sub;			/* true=顶层：收集 ~~* 子目录名；false=查 <pkg>- */
	const char *pkg;
	size_t pkg_len;
	int nsub;
	char sub[HTFG_APK_SUB_MAX][HTFG_APK_SUB_NAME];	/* 子目录名（仅名字） */
	char hit[HTFG_PATH_MAX];
};

static bool htfg_apk_name_match(const struct htfg_apk_scan *sc,
				const char *name, int namlen)
{
	return (size_t)namlen > sc->pkg_len &&
	       memcmp(name, sc->pkg, sc->pkg_len) == 0 &&
	       name[sc->pkg_len] == '-';
}

static int htfg_apk_scan_actor(struct dir_context *ctx, const char *name,
			       int namlen, loff_t off, u64 ino,
			       unsigned int d_type)
{
	struct htfg_apk_scan *sc =
		container_of(ctx, struct htfg_apk_scan, ctx);
	int n;

	if (d_type != DT_DIR || sc->hit[0] != '\0')
		return 0;

	/* Android 11+ 布局：/data/app/~~<hash>==/<pkg>-<hash>==/base.apk。
	 * 顶层收集 "~~" 前缀的子目录（实测名形如 ~~9sZOy8SLYhSLYiqxrpe1MQ==，
	 * 26 字符；超长异常名跳过，fail-closed）。 */
	if (sc->want_sub && namlen > 2 &&
	    namlen < (int)sizeof(sc->sub[0]) &&
	    name[0] == '~' && name[1] == '~') {
		if (sc->nsub < HTFG_APK_SUB_MAX) {
			memcpy(sc->sub[sc->nsub], name, namlen);
			sc->sub[sc->nsub][namlen] = '\0';
			sc->nsub++;
		}
		return 0;
	}

	if (htfg_apk_name_match(sc, name, namlen)) {
		n = snprintf(sc->hit, HTFG_PATH_MAX, "%s/%.*s/base.apk",
			     sc->parent, namlen, name);
		if (n <= 0 || n >= HTFG_PATH_MAX)
			sc->hit[0] = '\0';
	}
	return 0;
}

/* 扫 /data/app 找到 pkg 已安装副本的 base.apk 完整路径：
 *   第一遍：顶层收集 ~~<hash> 子目录名；
 *   第二遍：逐个进子目录找 "<pkg>-<hash>" 目录（另兼容顶层平铺的旧布局）。
 * 两遍分开遍历（绝不嵌套持有目录锁）；每次 iterate 前把续读游标归零。 */
static bool htfg_apk_path(char *out, size_t out_sz, const char *pkg,
			  const struct cred *cred)
{
	struct htfg_apk_scan *sc;
	struct file *df;
	int i;
	bool found = false;

	if (!pkg || !pkg[0])
		return false;

	sc = kzalloc(sizeof(*sc), GFP_KERNEL);
	if (!sc)
		return false;

	sc->ctx.actor = htfg_apk_scan_actor;
	sc->parent = "/data/app";
	sc->want_sub = true;
	sc->pkg = pkg;
	sc->pkg_len = strlen(pkg);

	df = htfg_kopen("/data/app", O_RDONLY, cred);
	if (!IS_ERR(df)) {
		sc->ctx.pos = 0;
		iterate_dir(df, &sc->ctx);
		filp_close(df, NULL);
	}

	sc->want_sub = false;
	for (i = 0; i < sc->nsub && sc->hit[0] == '\0'; i++) {
		char subpath[HTFG_PATH_MAX];
		int n;

		n = snprintf(subpath, HTFG_PATH_MAX, "/data/app/%s",
			     sc->sub[i]);
		if (n <= 0 || n >= HTFG_PATH_MAX)
			continue;
		sc->parent = subpath;
		df = htfg_kopen(subpath, O_RDONLY, cred);
		if (IS_ERR(df))
			continue;
		sc->ctx.pos = 0;	/* 修复：复用 ctx 时必须重置续读游标 */
		iterate_dir(df, &sc->ctx);
		filp_close(df, NULL);
	}

	if (sc->hit[0] != '\0') {
		strscpy(out, sc->hit, out_sz);
		found = true;
	}
	kfree(sc);
	return found;
}

/*
 * 借一个 system_server 进程的凭据（只读 /data 系统文件所需最小特权；与
 * kthread 的 prepare_kernel_cred(daemon) 同一套"借用他人 cred"通行范式）。
 * 匹配条件：comm == "system_server" 且 uid == 1000——comm 可被任何进程伪造、
 * uid 不能，两者同时满足才可取用。
 */
static const struct cred *htfg_borrow_system_cred(void)
{
	struct task_struct *p;
	struct task_struct *cand = NULL;
	const struct cred *cred;

	rcu_read_lock();
	for_each_process(p) {
		if (p->flags & PF_KTHREAD)
			continue;
		if (strcmp(p->comm, "system_server") != 0)
			continue;
		get_task_struct(p);
		cand = p;
		break;
	}
	rcu_read_unlock();

	if (!cand)
		return NULL;

	cred = get_task_cred(cand);
	put_task_struct(cand);
	if (cred && __kuid_val(cred->uid) != 1000) {
		put_cred(cred);
		cred = NULL;
	}
	return cred;
}

/*
 * 冷路径：完整验一遍调用者身份（可睡眠；不持任何锁、除 borrowed 外不持任何
 * 引用）。只在 system_wq worker 里运行（调用者线程不做 override_creds/文件 I/O）。
 * 一切失败都不区分原因（对外统一 EINVAL）：系统文件不可读、包查不到、apk
 * 找不到、签名不符……均归为"拒绝"（fail-closed）。
 */
static bool htfg_verify_identity(u32 uid)
{
	const struct cred *borrowed;
	const struct cred *old;
	char pkg[HTFG_PKG_MAX];
	char apk[HTFG_PATH_MAX];
	struct file *fp;
	bool ok = false;

	borrowed = htfg_borrow_system_cred();
	if (!borrowed)
		return false;

	old = override_creds(borrowed);

	fp = htfg_kopen("/data/system/packages.list",
			O_RDONLY | O_NOATIME, borrowed);
	if (!IS_ERR(fp)) {
		if (htfg_pkg_by_uid(fp, uid, pkg) &&
		    htfg_apk_path(apk, sizeof(apk), pkg, borrowed) &&
		    htfg_apk_check_signature(apk, borrowed))
			ok = true;
		filp_close(fp, NULL);
	}

	revert_creds(old);
	put_cred(borrowed);
	return ok;
}

/* 验证缓存：uid → 结论 + 过期时刻（uid 全局唯一，多用户/工作资料亦不撞） */
struct htfg_vslot {
	u32 uid;
	u8 ok;
	unsigned long expires;
};

static struct htfg_vslot htfg_vslots[HTFG_VERIFY_SLOTS];
static DEFINE_SPINLOCK(htfg_vslots_lock);

/* 1=已验证通过, 0=已验证失败, -1=无有效记录（需走冷路径） */
static int htfg_vslot_check(u32 uid)
{
	int ret = -1;
	int i;

	spin_lock(&htfg_vslots_lock);
	for (i = 0; i < HTFG_VERIFY_SLOTS; i++) {
		if (htfg_vslots[i].expires &&
		    htfg_vslots[i].uid == uid &&
		    time_before(jiffies, htfg_vslots[i].expires)) {
			ret = htfg_vslots[i].ok ? 1 : 0;
			break;
		}
	}
	spin_unlock(&htfg_vslots_lock);
	return ret;
}

static void htfg_vslot_store(u32 uid, bool ok)
{
	int idx = -1;
	int i;

	spin_lock(&htfg_vslots_lock);
	for (i = 0; i < HTFG_VERIFY_SLOTS; i++) {
		if (htfg_vslots[i].expires && htfg_vslots[i].uid == uid) {
			idx = i;
			break;
		}
	}
	if (idx < 0) {
		for (i = 0; i < HTFG_VERIFY_SLOTS; i++) {
			if (!htfg_vslots[i].expires) {
				idx = i;
				break;
			}
		}
	}
	if (idx < 0) {			/* 全满：踢最早过期者 */
		idx = 0;
		for (i = 1; i < HTFG_VERIFY_SLOTS; i++) {
			if (time_before(htfg_vslots[i].expires,
					htfg_vslots[idx].expires))
				idx = i;
		}
	}
	htfg_vslots[idx].uid = uid;
	htfg_vslots[idx].ok = ok ? 1 : 0;
	htfg_vslots[idx].expires =
		jiffies + (ok ? HTFG_VERIFY_TTL : HTFG_VERIFY_NEG_TTL);
	spin_unlock(&htfg_vslots_lock);
}

/*
 * 冷验签请求（异步）：调用者线程绝不 override_creds、绝不做文件 I/O——
 * 否则同进程的其他线程能从 /proc/self/task/<tid>/status 读到 system_server
 * 的 Uid/CapEff，且冷路径 1.7–5.1 ms 的离群可被计时。这里只把 uid 投进
 * system_wq，由 worker 完成验签并写回缓存。
 */
struct htfg_vreq {
	struct work_struct work;
	u32 uid;
	bool busy;
};

static struct htfg_vreq htfg_vreqs[HTFG_VERIFY_SLOTS];
static DEFINE_SPINLOCK(htfg_vreq_lock);

static void htfg_verify_worker(struct work_struct *work)
{
	struct htfg_vreq *req = container_of(work, struct htfg_vreq, work);
	bool ok = htfg_verify_identity(req->uid);

	htfg_vslot_store(req->uid, ok);

	spin_lock(&htfg_vreq_lock);
	req->busy = false;
	spin_unlock(&htfg_vreq_lock);
}

/* 投递一次冷验签（同 uid 去重；槽满静默丢弃，下次未命中会再投） */
static void htfg_verify_queue(u32 uid)
{
	int i;

	spin_lock(&htfg_vreq_lock);
	for (i = 0; i < HTFG_VERIFY_SLOTS; i++) {
		if (htfg_vreqs[i].busy && htfg_vreqs[i].uid == uid) {
			spin_unlock(&htfg_vreq_lock);
			return;
		}
	}
	for (i = 0; i < HTFG_VERIFY_SLOTS; i++) {
		if (!htfg_vreqs[i].busy) {
			htfg_vreqs[i].uid = uid;
			htfg_vreqs[i].busy = true;
			/*
			 * worker 函数末尾清 busy 与 work 框架清 PENDING 之间有一个
			 * 极短窗口：此时 queue_work 会返回 false（work 仍在运行）。
			 * 若不管返回值，该槽会永久 busy 泄漏；这里回退 busy 让下次
			 * 未命中可以重投（重复投递本身是无害的）。
			 */
			if (!queue_work(system_wq, &htfg_vreqs[i].work))
				htfg_vreqs[i].busy = false;
			break;
		}
	}
	spin_unlock(&htfg_vreq_lock);
}

/* 只初始化 .bss 里的 work 槽位；无设备/节点/文件/日志 */
static int __init htfg_init(void)
{
	int i;

	for (i = 0; i < HTFG_VERIFY_SLOTS; i++)
		INIT_WORK(&htfg_vreqs[i].work, htfg_verify_worker);
	return 0;
}
device_initcall(htfg_init);

/*
 * 身份判据（prctl 入口第一道门；三条路任一满足即放行）：
 *   a) 工具身份（root 0 / shell 2000；不含 App uid）；
 *   b) 验证缓存命中（TTL 内；含"已验证失败"的负缓存）；
 *   c) 缓存未命中 → 把冷验签投进 system_wq 后立即拒绝（本次 -EINVAL）；
 *      客户端对通道级 EINVAL 做短重试，worker 完成后同一 TTL 内全部命中。
 */
static bool htfg_identity_allowed(void)
{
	u32 uid;
	int verdict;

	if (htfg_uid_allowed())
		return true;

	uid = (u32)__kuid_val(current_euid());

	verdict = htfg_vslot_check(uid);
	if (verdict >= 0)
		return verdict == 1;

	htfg_verify_queue(uid);
	return false;
}

/* ============================================================ prctl 入口 */

/*
 * prctl() 的 HTFG 入口。
 * 调用点：kernel/sys.c 的 SYSCALL_DEFINE5(prctl, ...) 里、LSM 钩子之前。
 *
 * 分发顺序（钉死，协议文档 §2.3）：
 *   身份校验（工具身份 0/2000 或验签缓存；未命中则异步排队并立即拒绝）→ v1 标量
 *   ping → 指针下限 → copy_from_user → tag → op 分派 → copy_to_user。
 *   op 级结果表明在 kop.out；本函数只在"通道级"失败时返回负 errno。
 *   未授权统一 -EINVAL：与 stock 未知 prctl option 不可区分（不暴露身份门存在）。
 *
 * noinline 是为了让它出现在 System.map 里，方便构建后 grep 验证。
 */
noinline long ksu_htfg_prctl(unsigned long arg2, unsigned long arg3,
			 unsigned long arg4, unsigned long arg5)
{
	struct htfg_op kop;

	if (!htfg_identity_allowed())
		return -EINVAL;		/* 与 stock 未知 prctl option 一致 */

	/* v1 标量兼容：行为与第 1 步完全一致 */
	if (arg2 == HTFG_CMD_PING)
		return HTFG_PING_REPLY;

	/* 以下 arg2 一律应当是指向 struct htfg_op 的用户指针 */
	if (arg2 < PAGE_SIZE)
		return -EINVAL;
	if (copy_from_user(&kop, (void __user *)arg2, sizeof(kop)))
		return -EFAULT;

	kop.count = 0;
	kop.out = 0;
	if (kop.tag != HTFG_ABI_TAG) {
		kop.out = (uint32_t)-EINVAL;
	} else {
		switch (kop.op) {
		case HTFG_OP_PING:
			kop.count = HTFG_PRCTL_MAGIC;
			break;
		case HTFG_OP_READ_MEM:
			htfg_op_read_mem(&kop);
			break;
		case HTFG_OP_FIND_PID:
			htfg_op_find_pid(&kop);
			break;
		case HTFG_OP_GET_VMAS:
			htfg_op_get_vmas(&kop);
			break;
		case HTFG_OP_TOUCH_DEV:
			htfg_op_touch_dev(&kop);
			break;
		case HTFG_OP_TOUCH_SEND:
			htfg_op_touch_send(&kop);
			break;
		default:
			kop.out = (uint32_t)-EINVAL;
			break;
		}
	}

	if (copy_to_user((void __user *)arg2, &kop, sizeof(kop)))
		return -EFAULT;
	return 0;
}
