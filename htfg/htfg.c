// SPDX-License-Identifier: GPL-2.0
/*
 * HTFG —— 内核侧最小通道（第 1 步：只做 ping）
 *
 * 放置位置：内核树的 drivers/htfg/htfg.c
 *
 * 本步的设计约束（刻意做到"零风险"）：
 *   - 不读任何内存、不碰任何内核数据结构，只返回一个常量，不可能导致 panic；
 *   - 一个 printk 都不写（验收要求 dmesg 零输出）；
 *   - 拦截发生在 LSM 钩子之前，因此不需要任何 SELinux 规则；
 *   - 只有把 prctl 的第一个参数写成魔数才会命中，正常程序不可能误触。
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/htfg.h>

/*
 * 允许使用本通道的 uid 白名单。
 *
 * 第 1 步：0(root) 与 2000(shell) 用于命令行验证；
 * 10312 是测试 App（MyApplication，u0_a312）——仅第 1 步验证用，
 * 接入正式 App 时把这一行换成正式 App 的 uid（App 重装后 uid 可能变化）。
 */
static bool htfg_uid_allowed(void)
{
	kuid_t uid = current_euid();

	return uid_eq(uid, GLOBAL_ROOT_UID) ||
	       uid_eq(uid, KUIDT_INIT(2000)) ||
	       uid_eq(uid, KUIDT_INIT(10312));
}

/*
 * prctl() 的 HTFG 入口。
 * 调用点：kernel/sys.c 的 SYSCALL_DEFINE5(prctl, ...) 里、LSM 钩子之前。
 *
 * noinline 是为了让它出现在 System.map 里，方便构建后 grep 验证。
 */
noinline long htfg_prctl(unsigned long arg2, unsigned long arg3,
			 unsigned long arg4, unsigned long arg5)
{
	if (!htfg_uid_allowed())
		return -EPERM;

	switch (arg2) {
	case HTFG_CMD_PING:
		return HTFG_PING_REPLY;
	default:
		return -EINVAL;
	}
}
