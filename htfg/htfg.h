/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HTFG —— 内核侧通道定义（第 1 步：只有 ping）
 *
 * 放置位置：内核树的 include/linux/htfg.h
 *
 * 这些常量同时被内核与用户态工具使用，改这里必须同步改：
 *   - tools/htfgctl/htfgctl.c
 *   - MyApplication/app/src/main/java/com/baidu/myapplicationtest/MainActivity.java
 */
#ifndef _LINUX_HTFG_H
#define _LINUX_HTFG_H

/* prctl() 的第一个参数（int option）使用这个魔数：'HTFG' = 0x48544647 = 1213482567
 * 选它是因为它是正数，能安全地同时用 int / long 返回给用户态。 */
#define HTFG_PRCTL_MAGIC	0x48544647

/* 命令码，放在 prctl() 的第二个参数 */
#define HTFG_CMD_PING		1

/* HTFG_CMD_PING 的返回值：直接用系统调用返回值返回，不需要用户态指针 */
#define HTFG_PING_REPLY		HTFG_PRCTL_MAGIC

#ifdef __KERNEL__
long htfg_prctl(unsigned long arg2, unsigned long arg3,
		unsigned long arg4, unsigned long arg5);
#endif

#endif /* _LINUX_HTFG_H */
