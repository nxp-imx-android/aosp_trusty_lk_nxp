// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023 NXP
 */

#include <string.h>
#include <stdio.h>
#include <platform.h>
#include <kernel/spinlock.h>
#include "imx_mu.h"

#define RX_TIMEOUT (100)

#if defined(MACH_IMX8ULP) || defined(MACH_IMX93)
#define MU_TCR		  0x120
#define MU_TSR		  0x124
#define MU_RCR		  0x128
#define MU_RSR		  0x12C
#define MU_TR(n)	  (0x200 + 0x4 * (n))
#define MU_RR(n)	  (0x280 + 0x4 * (n))
#define MU_TSR_TE(n)	  (1U << (n))
#define MU_RSR_RF(n)	  (1U << (n))
#define MU_MAX_RX_CHANNEL 4
#define MU_MAX_TX_CHANNEL 8
#endif

static spin_lock_t mu_spinlock;

static bool timeout_elapsed(lk_time_ns_t timeout) {
	return current_time() > timeout;
}

#if defined(MACH_IMX8ULP) || defined(MACH_IMX93)
static int mu_wait_for(vaddr_t addr, uint32_t mask)
{
	lk_time_ns_t timeout = current_time() + 1;

	while (!(readl(addr) & mask))
		if (timeout_elapsed(timeout))
			break;

	if (readl(addr) & mask)
		return 0;
	else
		return -1;
}

void imx_mu_plat_init(vaddr_t base)
{
	/* Reset status registers */
	writel(0x0, base + MU_TCR);
	writel(0x0, base + MU_RCR);
}

unsigned int imx_mu_plat_get_rx_channel(void)
{
	return MU_MAX_RX_CHANNEL;
}

unsigned int imx_mu_plat_get_tx_channel(void)
{
	return MU_MAX_TX_CHANNEL;
}

int imx_mu_plat_send(vaddr_t base,
			unsigned int index,
			uint32_t msg)
{
	assert(index < MU_MAX_TX_CHANNEL);

	/* Wait TX register to be empty */
	if (mu_wait_for(base + MU_TSR, MU_TSR_TE(index)))
		return -1;

	writel(msg, base + MU_TR(index));

	return 0;
}

int imx_mu_plat_receive(vaddr_t base, unsigned int index, uint32_t *msg)
{
	assert(index < MU_MAX_RX_CHANNEL);

	/* Wait RX register to be full */
	if (mu_wait_for(base + MU_RSR, MU_RSR_RF(index)))
		return -1;

	*msg = readl(base + MU_RR(index));

	return 0;
}
#endif

/*
 * Receive a message via the MU
 *
 * @base: virtual base address of the MU controller
 * @[out]msg: message received
 */
static int imx_mu_receive_msg(vaddr_t base, struct imx_mu_msg *msg)
{
	int res = -1;
	unsigned int count = 0;
	uint32_t response = 0;
	unsigned int nb_channel = 0;
	lk_time_ns_t tout_rx = current_time() + RX_TIMEOUT;

	assert(base && msg);

	do {
		res = imx_mu_plat_receive(base, 0, &response);
		if (timeout_elapsed(tout_rx))
			break;
	} while (res != 0);

	if (res)
		return res;

	memcpy(&msg->header, &response, sizeof(response));

	/* Check the size of the message to receive */
	if (msg->header.size > IMX_MU_MSG_SIZE) {
		printf("Size of the message is > than IMX_MU_MSG_SIZE");
		return -1;
	}

	nb_channel = imx_mu_plat_get_rx_channel();

	for (count = 1; count < msg->header.size; count++) {
		res = imx_mu_plat_receive(base, count % nb_channel,
					  &msg->data.u32[count - 1]);
		if (res)
			return res;
	}

	return 0;
}

/*
 * Send a message via the MU
 *
 * @base: virtual base address of the MU controller
 * @[in]msg: message to send
 */
static int imx_mu_send_msg(vaddr_t base, struct imx_mu_msg *msg)
{
	int res = 0;
	unsigned int count = 0;
	unsigned int nb_channel = 0;
	uint32_t word = 0;

	assert(base && msg);

	if (msg->header.size > IMX_MU_MSG_SIZE) {
		printf("%s: msg->size is larger than IMX_MU_MSG_SIZE\n", __func__);
		return -1;
	}

	memcpy(&word, &msg->header, sizeof(uint32_t));
	res = imx_mu_plat_send(base, 0, word);
	if (res)
		return res;

	nb_channel = imx_mu_plat_get_tx_channel();

	for (count = 1; count < msg->header.size; count++) {
		res = imx_mu_plat_send(base, count % nb_channel,
				       msg->data.u32[count - 1]);
		if (res)
			return res;
	}

	return 0;
}

void imx_mu_init(vaddr_t base)
{
	spin_lock_saved_state_t state;

	if (!base) {
		printf("%s: MU base address is wrong!\n", __func__);
	}

	spin_lock_save(&mu_spinlock, &state, SPIN_LOCK_FLAG_IRQ_FIQ);
	imx_mu_plat_init(base);
	spin_unlock_restore(&mu_spinlock, state, SPIN_LOCK_FLAG_IRQ_FIQ);
}

int imx_mu_call(vaddr_t base, struct imx_mu_msg *msg,
		bool wait_for_answer)
{
	int res = 0;
	spin_lock_saved_state_t state;

	if (!base || !msg) {
		printf("%s: wrong parameters!\n", __func__);
		return -1;
	}

	spin_lock_save(&mu_spinlock, &state, SPIN_LOCK_FLAG_IRQ_FIQ);

	res = imx_mu_send_msg(base, msg);
	if (res == 0 && wait_for_answer)
		res = imx_mu_receive_msg(base, msg);

	spin_unlock_restore(&mu_spinlock, state, SPIN_LOCK_FLAG_IRQ_FIQ);

	return res;
}
