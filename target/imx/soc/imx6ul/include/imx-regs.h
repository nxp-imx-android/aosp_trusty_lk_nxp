/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2017 NXP
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _IMX_REGS_H_
#define _IMX_REGS_H_

#define GIC_BASE_PHY 0xa01000
#define GIC_BASE_VIRT 0x70a01000

#define SOC_REGS_PHY  0x02000000
#define SOC_REGS_VIRT 0x72000000
#define SOC_REGS_SIZE 0x00100000

/* Registers for GIC */
#define MAX_INT 160
#define GICBASE(b) (GIC_BASE_VIRT)

#define GICC_SIZE (0x1000)
#define GICD_SIZE (0x100)

#define GICC_OFFSET (0x1000)
#define GICD_OFFSET (0x0000)

#define GICC_BASE_VIRT (GIC_BASE_VIRT + GICC_OFFSET)
#define GICD_BASE_VIRT (GIC_BASE_VIRT + GICD_OFFSET)

#define GIC_REG_SIZE 0x2000

/* Registers for TZASC */
#define TZ_BASE ((0x02100000 + 0x80000) + 0x50000)
#define TZ_BASE_VIRT (0x70000000 + TZ_BASE)
#define TZ_REG_SIZE 0x4000
#define TZ_BYPASS_GPR_BASE 0x20E4024
#define TZ_BYPASS_GPR_BASE_VIRT (0x70000000 + TZ_BYPASS_GPR_BASE)

#endif
