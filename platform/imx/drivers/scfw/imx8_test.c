/*
 * Copyright 2019 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dev/uart.h>
#include <kernel/thread.h>
#include <platform/debug.h>
#include <lib/sm/smcall.h>
#include <lib/sm.h>
#include <lk/init.h>
#include <imx-regs.h>
#include <reg.h>
#include <sci/rpc.h>
#include <sci/svc/seco/api.h>
#include <sci/svc/misc/api.h>

void scfw_test(uint level)
{
	u32 version = 0, commit = 0;
	sc_ipc_t ipc_handle;

	if (sc_ipc_open(&ipc_handle, SC_IPC_BASE) != SC_ERR_NONE) {
		fprintf(stderr, "ipc port open error\n");
		return;
	}

	sc_misc_build_info(ipc_handle, &version, &commit);
	if (version == 0)
		fprintf(stderr, "SCFW doesn't support version.\n");
	else
		fprintf(stderr, "SCFW: %08x\n", commit);

	sc_seco_build_info(ipc_handle, &version, &commit);
	if (version == 0)
		fprintf(stderr, "SECO-FW doesn't support version.\n");
	else
		fprintf(stderr, "SECO-FW: %08x\n", commit);
}

LK_INIT_HOOK(scfw_test, scfw_test, LK_INIT_LEVEL_PLATFORM);
