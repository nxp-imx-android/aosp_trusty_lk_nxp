/*
 * Copyright (c) 2012-2016, Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * o Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * o Neither the name of Freescale Semiconductor, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
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

#ifndef __CAAM_INTERNAL_H__
#define __CAAM_INTERNAL_H__

static uint8_t* caam_base;
#if defined(MACH_IMX7D)
static uint8_t* ccm_base;
#endif
static uint8_t* sram_base;

/* 4kbyte pages */
#define CAAM_SEC_RAM_START_ADDR (sram_base)

#define SEC_MEM_PAGE0 CAAM_SEC_RAM_START_ADDR
#define SEC_MEM_PAGE1 (CAAM_SEC_RAM_START_ADDR + 0x1000)
#define SEC_MEM_PAGE2 (CAAM_SEC_RAM_START_ADDR + 0x2000)
#define SEC_MEM_PAGE3 (CAAM_SEC_RAM_START_ADDR + 0x3000)

/* Configuration and special key registers */
#define CAAM_MCFGR (0x0004 + caam_base)
#define CAAM_SCFGR (0x000c + caam_base)
#define CAAM_JR0MIDR (0x0010 + caam_base)
#define CAAM_JR0LIDR (0x0014 + caam_base)
#define CAAM_JR1MIDR (0x0018 + caam_base)
#define CAAM_JR2MIDR (0x0020 + caam_base)
#define CAAM_JR2LIDR (0x0024 + caam_base)
#define CAAM_DECORR (0x009c + caam_base)
#define CAAM_DECO0MID (0x00a0 + caam_base)
#define CAAM_DAR (0x0120 + caam_base)
#define CAAM_DRR (0x0124 + caam_base)
#define CAAM_JDKEKR (0x0400 + caam_base)
#define CAAM_TDKEKR (0x0420 + caam_base)
#define CAAM_TDSKR (0x0440 + caam_base)
#define CAAM_SKNR (0x04e0 + caam_base)
#define CAAM_SMSTA (0x0FB4 + caam_base)
#define CAAM_STA (0x0FD4 + caam_base)
#define CAAM_SMPO_0 (0x1FBC + caam_base)

/* RNG registers */
#define CAAM_RTMCTL (0x0600 + caam_base)
#define CAAM_RTSDCTL (0x0610 + caam_base)
#define CAAM_RTFRQMIN (0x0618 + caam_base)
#define CAAM_RTFRQMAX (0x061C + caam_base)
#define CAAM_RTSTATUS (0x063C + caam_base)
#define CAAM_RDSTA (0x06C0 + caam_base)

/* Job Ring 0 registers */
#define CAAM_IRBAR0 (0x1004 + caam_base)
#define CAAM_IRSR0 (0x100c + caam_base)
#define CAAM_IRSAR0 (0x1014 + caam_base)
#define CAAM_IRJAR0 (0x101c + caam_base)
#define CAAM_ORBAR0 (0x1024 + caam_base)
#define CAAM_ORSR0 (0x102c + caam_base)
#define CAAM_ORJRR0 (0x1034 + caam_base)
#define CAAM_ORSFR0 (0x103c + caam_base)
#define CAAM_JRSTAR0 (0x1044 + caam_base)
#define CAAM_JRINTR0 (0x104c + caam_base)
#define CAAM_JRCFGR0_MS (0x1050 + caam_base)
#define CAAM_JRCFGR0_LS (0x1054 + caam_base)
#define CAAM_IRRIR0 (0x105c + caam_base)
#define CAAM_ORWIR0 (0x1064 + caam_base)
#define CAAM_JRCR0 (0x106c + caam_base)
#define CAAM_SMCJR0 (0x10f4 + caam_base)
#define CAAM_SMCSJR0 (0x10fc + caam_base)
/* Job Ring 2 registers */
#define CAAM_IRBAR2 (0x3004 + caam_base)
#define CAAM_IRSR2 (0x300c + caam_base)
#define CAAM_IRSAR2 (0x3014 + caam_base)
#define CAAM_IRJAR2 (0x301c + caam_base)
#define CAAM_ORBAR2 (0x3024 + caam_base)
#define CAAM_ORSR2 (0x302c + caam_base)
#define CAAM_ORJRR2 (0x3034 + caam_base)
#define CAAM_ORSFR2 (0x303c + caam_base)
#define CAAM_JRSTAR2 (0x3044 + caam_base)
#define CAAM_JRINTR2 (0x304c + caam_base)
#define CAAM_JRCFGR2_MS (0x3050 + caam_base)
#define CAAM_JRCFGR2_LS (0x3054 + caam_base)
#define CAAM_IRRIR2 (0x305c + caam_base)
#define CAAM_ORWIR2 (0x3064 + caam_base)
#define CAAM_JRCR2 (0x306c + caam_base)
#if 0
#define CAAM_SMAPJR0(y) (CAAM_BASE_ADDR + 0x1104 + y * 16)
#define CAAM_SMAG2JR0(y) (CAAM_BASE_ADDR + 0x1108 + y * 16)
#define CAAM_SMAG1JR0(y) (CAAM_BASE_ADDR + 0x110C + y * 16)
#define CAAM_SMAPJR0_PRTN1 CAAM_BASE_ADDR + 0x1114
#define CAAM_SMAG2JR0_PRTN1 CAAM_BASE_ADDR + 0x1118
#define CAAM_SMAG1JR0_PRTN1 CAAM_BASE_ADDR + 0x111c
#define CAAM_SMPO CAAM_BASE_ADDR + 0x1fbc
#endif

#ifdef MACH_IMX8Q
/* imx8q Job Ring 3 registers */
#define CAAM_IRBAR3 (0x40004 + caam_base)
#define CAAM_IRSR3 (0x4000c + caam_base)
#define CAAM_IRJAR3 (0x4001c + caam_base)
#define CAAM_ORBAR3 (0x40024 + caam_base)
#define CAAM_ORSR3 (0x4002c + caam_base)
#define CAAM_ORSFR3 (0x4003c + caam_base)
#define CAAM_ORJRR3 (0x40034 + caam_base)
#endif

#ifdef MACH_IMX8Q
#define CAAM_IRBAR CAAM_IRBAR3
#define CAAM_ORBAR CAAM_ORBAR3
#define CAAM_IRSR  CAAM_IRSR3
#define CAAM_ORSR  CAAM_ORSR3
#define CAAM_IRJAR CAAM_IRJAR3
#define CAAM_ORSFR CAAM_ORSFR3
#define CAAM_ORJRR CAAM_ORJRR3
#else
#define CAAM_IRBAR CAAM_IRBAR2
#define CAAM_ORBAR CAAM_ORBAR2
#define CAAM_IRSR  CAAM_IRSR2
#define CAAM_ORSR  CAAM_ORSR2
#define CAAM_IRJAR CAAM_IRJAR2
#define CAAM_ORSFR CAAM_ORSFR2
#define CAAM_ORJRR CAAM_ORJRR2
#endif

#define JRCFG_LS_IMSK 0x00000001
#define JR_MID 2
#define KS_G1 (1UL << JR_MID)
#define PERM 0x0000B008

#define CMD_PAGE_ALLOC 0x1
#define CMD_PAGE_DEALLOC 0x2
#define CMD_PART_DEALLOC 0x3
#define CMD_INQUIRY 0x5
#define PAGE(x) (x << 16)
#define PARTITION(x) (x << 8)

#define SMCSJR_AERR (3UL << 12)
#define SMCSJR_CERR (3UL << 14)
#define CMD_COMPLETE (3UL << 14)

#define SMCSJR_PO (3UL << 6)
#define PAGE_AVAILABLE 0
#define PAGE_OWNED (3UL << 6)

#define PARTITION_OWNER(x) (0x3UL << (x * 2))

#define CAAM_BUSY_MASK 0x00000001
#define CAAM_IDLE_MASK 0x00000002
#define JOB_RING_ENTRIES 1
#define JOB_RING_STS (0xFUL << 28)

#define RNG_TRIM_OSC_DIV 0
#define RNG_TRIM_ENT_DLY 3200

#define RTMCTL_PGM (1UL << 16)
#define RTMCTL_ERR (1UL << 12)
#define RDSTA_IF0 1
#define RDSTA_SKVN (1UL << 30)

#define DECAP_BLOB_DESC1 0xB0800009
#define DECAP_BLOB_DESC2 0x14C00C08
#define DECAP_BLOB_DESC3 0x00105566
#define DECAP_BLOB_DESC4 0x00000000
#define DECAP_BLOB_DESC5 0xF0000400
#define DECAP_BLOB_DESC6 0x00000000
#define DECAP_BLOB_DESC7 0xF80003d0
#define DECAP_BLOB_DESC8 SEC_MEM_PAGE1
#define DECAP_BLOB_DESC9 0x860D0008

#define ENCAP_BLOB_DESC1 0xB0800009
#define ENCAP_BLOB_DESC2 0x14C00C08
#define ENCAP_BLOB_DESC3 0x00105566
#define ENCAP_BLOB_DESC4 0x00000000
#define ENCAP_BLOB_DESC5 0xF00003d0
#define ENCAP_BLOB_DESC6 SEC_MEM_PAGE1
#define ENCAP_BLOB_DESC7 0xF8000400
#define ENCAP_BLOB_DESC8 0x00000000
#define ENCAP_BLOB_DESC9 0x870D0008

#define RNG_INST_DESC1 0xB0800009
#define RNG_INST_DESC2 0x12A00008
#define RNG_INST_DESC3 0x01020304
#define RNG_INST_DESC4 0x05060708
#define RNG_INST_DESC5 0x82500404
#define RNG_INST_DESC6 0xA2000001
#define RNG_INST_DESC7 0x10880004
#define RNG_INST_DESC8 0x00000001
#define RNG_INST_DESC9 0x82501000

/*
 * According to CAAM docs max number of descriptors in single sequence is 64
 * You can chain them though
*/
#define MAX_DSC_NUM 64UL

#define CAAM_KB_HEADER_LEN 48
#define CAAM_SUCCESS 0
#define CAAM_FAILURE 1

#define CIPHER_ENCRYPT     0x1
#define CIPHER_DECRYPT     0UL

#define CAAM_CIPHER_ENCRYPT     1
#define CAAM_CIPHER_DECRYPT     0

/* Define key color, black keys are encrypted, while red keys are un-encrypted. */
#define RED_KEY					0
#define BLACK_KEY				1

#define HEADER_COMMAND 0xB0800000
#define HEADER_SET_DESC_LEN(command, len) (command |= (len & 0x7F))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define CCM_OVERHEAD			12UL /* Defines Balck key IV + MAC size. */

/* Define Encrypted Key Type */
#define ENCRYPTED_KEY_TYPE_ECB	0UL	 /* The Black Key is decrypted using AES-ECB */
#define ENCRYPTED_KEY_TYPE_CCM	1UL    /* The Black Key is decrypted using AES-CCM */

#define ALGORITHM_OPERATION_CMD_AAI_SHIFT	4

#define ALGORITHM_OPERATION_CMD_AAI_CBC         (0x10UL << ALGORITHM_OPERATION_CMD_AAI_SHIFT)
#define ALGORITHM_OPERATION_CMD_AAI_ECB         (0x20UL << ALGORITHM_OPERATION_CMD_AAI_SHIFT)
#define ALGORITHM_OPERATION_CMD_AAI_CFB         (0x30UL << ALGORITHM_OPERATION_CMD_AAI_SHIFT)
#define ALGORITHM_OPERATION_CMD_AAI_OFB         (0x40UL << ALGORITHM_OPERATION_CMD_AAI_SHIFT)
#define ALGORITHM_OPERATION_CMD_AAI_XTS         (0x50UL << ALGORITHM_OPERATION_CMD_AAI_SHIFT)
#define ALGORITHM_OPERATION_CMD_AAI_CMAC        (0x60UL << ALGORITHM_OPERATION_CMD_AAI_SHIFT)
#define ALGORITHM_OPERATION_CMD_AAI_XCBC_MAC    (0x70UL << ALGORITHM_OPERATION_CMD_AAI_SHIFT)
#define ALGORITHM_OPERATION_CMD_AAI_CCM         (0x80UL << ALGORITHM_OPERATION_CMD_AAI_SHIFT)
#define ALGORITHM_OPERATION_CMD_AAI_GCM         (0x90UL << ALGORITHM_OPERATION_CMD_AAI_SHIFT)

#define ALGORITHM_OPERATION_ALGSEL_SHIFT	16
#define ALGORITHM_OPERATION_ALGSEL_AES		(0x10UL << ALGORITHM_OPERATION_ALGSEL_SHIFT)
#define ALGORITHM_OPERATION_ALGSEL_DES		(0x20UL << ALGORITHM_OPERATION_ALGSEL_SHIFT)
#define ALGORITHM_OPERATION_ALGSEL_3DES		(0x21UL << ALGORITHM_OPERATION_ALGSEL_SHIFT)
#define ALGORITHM_OPERATION_ALGSEL_ARC4		(0x30UL << ALGORITHM_OPERATION_ALGSEL_SHIFT)
#define ALGORITHM_OPERATION_ALGSEL_MD5		(0x40UL << ALGORITHM_OPERATION_ALGSEL_SHIFT)
#define ALGORITHM_OPERATION_ALGSEL_SHA1		(0x41UL << ALGORITHM_OPERATION_ALGSEL_SHIFT)
#define ALGORITHM_OPERATION_ALGSEL_SHA224	(0x42UL << ALGORITHM_OPERATION_ALGSEL_SHIFT)
#define ALGORITHM_OPERATION_ALGSEL_SHA256	(0x43UL << ALGORITHM_OPERATION_ALGSEL_SHIFT)
#define ALGORITHM_OPERATION_ALGSEL_SHA384	(0x44UL << ALGORITHM_OPERATION_ALGSEL_SHIFT)
#define ALGORITHM_OPERATION_ALGSEL_SHA512	(0x45UL << ALGORITHM_OPERATION_ALGSEL_SHIFT)

#endif /* __CAAM_INTERNAL_H__ */
