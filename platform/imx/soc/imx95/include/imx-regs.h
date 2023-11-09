/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2023 NXP
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

#define MACH_IMX95

#define SOC_REGS_PHY 0x43800000
#ifdef ARCH_ARM64
#define SOC_REGS_VIRT (0xFFFFFFFF00000000 + SOC_REGS_PHY)
#else
#define SOC_REGS_VIRT (0x20000000 + SOC_REGS_PHY)
#endif
#define SOC_REGS_SIZE 0x9400000

/* console */
#ifdef ARCH_ARM64
#define CONFIG_CONSOLE_TTY_VIRT (0xFFFFFFFF00000000 + CONFIG_CONSOLE_TTY_BASE)
#else
#define CONFIG_CONSOLE_TTY_VIRT (0x20000000+ CONFIG_CONSOLE_TTY_BASE)
#endif

/* Registers for GIC */
#define MAX_INT 1020
#define GIC_BASE_PHY 0x48000000
#ifdef ARCH_ARM64
#define GIC_BASE_VIRT (0xFFFFFFFF00000000 + GIC_BASE_PHY)
#else
#define GIC_BASE_VIRT (0x20000000 + GIC_BASE_PHY)
#endif
#define GICBASE(b) (GIC_BASE_VIRT)

#define GICR_OFFSET (0x60000)

#define GICD_OFFSET (0x0000)
#define GICD_SIZE (0x10000)
#define GICD_BASE_VIRT (GIC_BASE_VIRT + GICD_OFFSET)

#define GICC_OFFSET (0x1000)
#define GICC_SIZE (0x1000)
#define GICC_BASE_VIRT (GIC_BASE_VIRT + GICC_OFFSET)
#define GIC_REG_SIZE 0x2000

/* Message Uint */
#define MU_BASE_VIRT 0xFFFFFFFF47530000
#define MU_SIZE      0x10000

#endif /* _IMX_REGS_H_ */
