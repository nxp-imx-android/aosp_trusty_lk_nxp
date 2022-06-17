/*
 * Copyright 2022 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>

#include <debug.h>
#include <err.h>
#include <kernel/vm.h>
#include <lib/trusty/sys_fd.h>
#include <lib/trusty/trusty_app.h>
#include <lk/init.h>
#include <mm.h>
#include <stdio.h>
#include <string.h>
#include <trace.h>
#include <platform/imx_xrdc.h>
#include <reg.h>
#include <lib/sm/smcall.h>
#include <lib/sm.h>
#include <imx-regs.h>
#include <uapi/trusty_uuid.h>

#define BIT_32(nr)	(1u << (nr))
#define MRC_OFFSET	0x2000
#define MRC_STEP	0x200

#define DRIVER_FD SYSCALL_PLATFORM_FD_XRDC
#define CHECK_FD(x) \
	do { if(x!=DRIVER_FD) return ERR_BAD_HANDLE; } while (0)
#define PRINT_TRUSTY_APP_UUID(tid, u)                                          \
	printf("trusty_app %d uuid: 0x%x 0x%x 0x%x 0x%x%x 0x%x%x%x%x%x%x\n", tid, \
	(u)->time_low, (u)->time_mid, (u)->time_hi_and_version,            \
	(u)->clock_seq_and_node[0], (u)->clock_seq_and_node[1],            \
	(u)->clock_seq_and_node[2], (u)->clock_seq_and_node[3],            \
	(u)->clock_seq_and_node[4], (u)->clock_seq_and_node[5],            \
	(u)->clock_seq_and_node[6], (u)->clock_seq_and_node[7]);

static struct uuid hwsecure_ta_uuid = {
	0xc52ae02f,
	0xfa45,
	0x4d8e,
	{0x93, 0xe0, 0x6b, 0x51, 0xcf, 0x7a, 0x92, 0x3b},
};

static uint64_t xrdc_base = (uint64_t)XRDC_BASE_VIRT;

static bool check_uuid_equal(const struct uuid* a, const struct uuid* b) {
	return memcmp(a, b, sizeof(struct uuid)) == 0;
}

uint32_t imx8ulp_pac_slots[]= {
	61, 23, 53
};

uint32_t imx8ulp_msc_slots[]= {
	2, 1, 7
};

static int xrdc_config_mrc_w0_w1(uint32_t mrc_con, uint32_t region, uint32_t w0, uint32_t size)
{

	uint64_t w0_addr, w1_addr;

	w0_addr = xrdc_base + MRC_OFFSET + mrc_con * 0x200 + region * 0x20;
	w1_addr = w0_addr + 4;

	if ((size % 32) != 0)
		return -EINVAL;

	writel(w0 & ~0x1f, w0_addr);
	writel(w0 + size - 1, w1_addr);

	return 0;
}

static int xrdc_config_mrc_w2(uint32_t mrc_con, uint32_t region, uint32_t dxsel_all)
{
	uint64_t w2_addr;

	w2_addr = xrdc_base + MRC_OFFSET + mrc_con * 0x200 + region * 0x20 + 0x8;

	writel(dxsel_all, w2_addr);

	return 0;
}

static int xrdc_config_mrc_w3_w4(uint32_t mrc_con, uint32_t region, uint32_t w3, uint32_t w4)
{
	uint64_t w3_addr = xrdc_base + MRC_OFFSET + mrc_con * 0x200 + region * 0x20 + 0xC;
	uint64_t w4_addr = w3_addr + 4;

	writel(w3, w3_addr);
	writel(w4, w4_addr);

	return 0;
}

static int xrdc_config_pac(uint32_t pac, uint32_t index, uint32_t dxacp)
{
	uint64_t w0_addr;
	uint32_t val;

	if (pac > 2)
		return -EINVAL;

	w0_addr = xrdc_base + 0x1000 + 0x400 * pac + 0x8 * index;

	writel(dxacp, w0_addr);

	val = readl(w0_addr + 4);
	writel(val | BIT_32(31), w0_addr + 4);

	return 0;
}

static int xrdc_config_msc(uint32_t msc, uint32_t index, uint32_t dxacp)
{
	uint64_t w0_addr;
	uint32_t val;

	if (msc > 2)
		return -EINVAL;

	w0_addr = xrdc_base + 0x4000 + 0x400 * msc + 0x8 * index;

	writel(dxacp, w0_addr);

	val = readl(w0_addr + 4);
	writel(val | BIT_32(31), w0_addr + 4);

	return 0;
}

static int xrdc_config_mda(uint32_t mda_con, uint32_t dom, enum xrdc_mda_sa sa)
{
	uint64_t w0_addr;
	uint32_t val;

	w0_addr = xrdc_base + 0x800 + mda_con * 0x20;

	val = readl(w0_addr);

	if (val & BIT_32(29)) {
		writel((val & (~0xFF)) | dom | BIT_32(31) | 0x20 | ((sa & 0x3) << 6), w0_addr);
	} else {
		writel(dom | BIT_32(31), w0_addr);
		writel(dom | BIT_32(31), w0_addr + 0x4);
	}

	return 0;
}

static int32_t imx_xrdc_mda(uint32_t cmd, user_addr_t user_ptr) {
	struct xrdc_mda_config *msg = (struct xrdc_mda_config *)user_ptr;

	xrdc_config_mda(msg->mda_id, msg->did, msg->sa);
	return 0;
}

static int32_t imx_xrdc_mrc(uint32_t cmd, user_addr_t user_ptr) {
	struct xrdc_mrc_config *msg = (struct xrdc_mrc_config *)user_ptr;
	int val = 0, j;

	xrdc_config_mrc_w0_w1(msg->mrc_id, msg->region_id, msg->region_start, msg->region_size);

	for (j = 0; j < DID_MAX; j++)
		val |= msg->dsel[j] << (3 * j);

	xrdc_config_mrc_w2(msg->mrc_id, msg->region_id, val);
	xrdc_config_mrc_w3_w4(msg->mrc_id, msg->region_id, 0, msg->accset[0] | (msg->accset[1] << 16) | BIT_32(31));

	return 0;
}

static int32_t imx_xrdc_pdac(uint32_t cmd, user_addr_t user_ptr) {
	uint32_t val = 0, j;
	struct xrdc_pac_msc_config *msg = (struct xrdc_pac_msc_config *)user_ptr;

	for (j = 0; j < DID_MAX; j++)
		val |= msg->dsel[j] << (3 * j);

	if (msg->slot_id == PAC_SLOT_ALL) {
		/* Apply to all slots*/
		for (j = 0; j < imx8ulp_pac_slots[msg->pac_msc_id]; j++)
			xrdc_config_pac(msg->pac_msc_id, j, val);
	} else {
		if (msg->slot_id >= imx8ulp_pac_slots[msg->pac_msc_id])
			return -EINVAL;
		xrdc_config_pac(msg->pac_msc_id, msg->slot_id, val);
	}
	return 0;
}

static int32_t imx_xrdc_msc(uint32_t cmd, user_addr_t user_ptr) {
	uint32_t val = 0, j;
	struct xrdc_pac_msc_config *msg = (struct xrdc_pac_msc_config *)user_ptr;

	for (j = 0; j < DID_MAX; j++)
		val |= msg->dsel[j] << (3 * j);

	if (msg->slot_id == MSC_SLOT_ALL) {
		/* Apply to all slots*/
		for (j = 0; j < imx8ulp_msc_slots[msg->pac_msc_id]; j++)
			xrdc_config_msc(msg->pac_msc_id, j, val);
	} else {
		if (msg->slot_id >= imx8ulp_msc_slots[msg->pac_msc_id])
			return -EINVAL;
		xrdc_config_msc(msg->pac_msc_id, msg->slot_id, val);
	}
	return 0;
}

static int32_t sys_xrdc_ioctl(uint32_t fd, uint32_t cmd, user_addr_t user_ptr) {

	struct trusty_app* app = current_trusty_app();
	CHECK_FD(fd);

	if (!check_uuid_equal(&app->props.uuid, &hwsecure_ta_uuid)) {
		printf("cmd %d is not allowed for application!", cmd);
		PRINT_TRUSTY_APP_UUID(app->app_id, &app->props.uuid);
		return -EINVAL;
	}

	switch (cmd) {
		case XRDC_IOCMD_CFG_MDA:
			return imx_xrdc_mda(cmd, user_ptr);
		case XRDC_IOCMD_CFG_MRC:
			return imx_xrdc_mrc(cmd, user_ptr);
		case XRDC_IOCMD_CFG_PDAC:
			return imx_xrdc_pdac(cmd, user_ptr);
		case XRDC_IOCMD_CFG_MSC:
			return imx_xrdc_msc(cmd, user_ptr);
		default:
			printf("cmd %d is not valid!", cmd);
			return -EINVAL;
	}
	return 0;
}

static const struct sys_fd_ops xrdc_ops = {
	.ioctl = sys_xrdc_ioctl,
};

void platform_init_xrdc(uint level) {
	install_sys_fd_handler(SYSCALL_PLATFORM_FD_XRDC, &xrdc_ops);
}

LK_INIT_HOOK(xrdc_dev_init, platform_init_xrdc, LK_INIT_LEVEL_PLATFORM + 1);

