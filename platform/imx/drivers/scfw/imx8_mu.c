/*
 * Copyright (c) 2015-2018, ARM Limited and Contributors. All rights reserved.
 * Copyright 2017-2019 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "imx8_mu.h"
#include <reg.h>

void MU_Resume(uint32_t base)
{
	uint32_t reg, i;

	reg = *RW32(base + MU_ACR_OFFSET1);
	/* Clear GIEn, RIEn, TIEn, GIRn and ABFn. */
	reg &= ~(MU_CR_GIEn_MASK1 | MU_CR_RIEn_MASK1 | MU_CR_TIEn_MASK1
			| MU_CR_GIRn_MASK1 | MU_CR_Fn_MASK1);
	*RW32(base + MU_ACR_OFFSET1) = reg;

	/* Enable all RX interrupts */
	for (i = 0; i < MU_RR_COUNT; i++) {
		MU_EnableRxFullInt(base, i);
	}
}

void MU_EnableRxFullInt(uint32_t base, uint32_t index)
{
	uint32_t reg = *RW32(base + MU_ACR_OFFSET1);

	reg &= ~(MU_CR_GIRn_MASK1 | MU_CR_NMI_MASK1);
	reg |= MU_CR_RIE0_MASK1 >> index;
	*RW32(base + MU_ACR_OFFSET1) =  reg;
}

void MU_EnableGeneralInt(uint32_t base, uint32_t index)
{
	uint32_t reg = *RW32(base + MU_ACR_OFFSET1);

	reg &= ~(MU_CR_GIRn_MASK1 | MU_CR_NMI_MASK1);
	reg |= MU_CR_GIE0_MASK1 >> index;
	*RW32(base + MU_ACR_OFFSET1) =  reg;
}

void MU_SendMessage(uint32_t base, uint32_t regIndex, uint32_t msg)
{
	uint32_t mask = MU_SR_TE0_MASK1 >> regIndex;

	/* Wait TX register to be empty. */
	while (!(*RW32(base + MU_ASR_OFFSET1) & mask))
		;
	*RW32(base + MU_ATR0_OFFSET1 + (regIndex * 4)) =  msg;
}

void MU_ReceiveMsg(uint32_t base, uint32_t regIndex, uint32_t *msg)
{
	uint32_t mask = MU_SR_RF0_MASK1 >> regIndex;

	/* Wait RX register to be full. */
	while (!(*RW32(base + MU_ASR_OFFSET1) & mask))
		;
	*msg = *RW32(base + MU_ARR0_OFFSET1 + (regIndex * 4));
}

void MU_Init(uint32_t base)
{
	uint32_t reg;

	reg = *RW32(base + MU_ACR_OFFSET1);
	/* Clear GIEn, RIEn, TIEn, GIRn and ABFn. */
	reg &= ~(MU_CR_GIEn_MASK1 | MU_CR_RIEn_MASK1 | MU_CR_TIEn_MASK1
			| MU_CR_GIRn_MASK1 | MU_CR_Fn_MASK1);
	*RW32(base + MU_ACR_OFFSET1) = reg;
}
