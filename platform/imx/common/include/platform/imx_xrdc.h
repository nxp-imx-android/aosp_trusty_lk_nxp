/*
 * Copyright 2022 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __IMX8ULP_XRDC_H__
#define __IMX8ULP_XRDC_H__

#define DID_MAX 8
#define PAC_SLOT_ALL 128
#define MSC_SLOT_ALL 8
#define SYSCALL_PLATFORM_FD_XRDC 8

#define SP(X)		((X) << 9)
#define SU(X)		((X) << 6)
#define NP(X)		((X) << 3)
#define NU(X)		((X) << 0)

#define RWX		7
#define RW		6
#define R		4
#define X		1

#define XRDC_IOCMD_CFG_MDA  0x00000001
#define XRDC_IOCMD_CFG_MRC  0x00000002
#define XRDC_IOCMD_CFG_PDAC 0x00000003
#define XRDC_IOCMD_CFG_MSC  0x00000004

enum xrdc_mda_sa{
	MDA_SA_S,
	MDA_SA_NS,
	MDA_SA_PT, /* pass through master's secure/nonsecure attribute */
};

struct xrdc_mda_config {
	uint16_t mda_id;
	uint16_t did;
	enum xrdc_mda_sa sa;
};

struct xrdc_pac_msc_config {
	uint16_t pac_msc_id;
	uint16_t slot_id;
	uint8_t dsel[DID_MAX];
};

struct xrdc_mrc_config {
	uint16_t mrc_id;
	uint16_t region_id;
	uint32_t region_start;
	uint32_t region_size;
	uint8_t dsel[DID_MAX];
	uint16_t accset[2];
};

#endif
