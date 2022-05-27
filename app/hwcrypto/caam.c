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

#include <assert.h>
#include <lk/compiler.h>
#include <lk/reg.h>
#include <malloc.h>
#include <openssl/digest.h>
#include <openssl/hkdf.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <trusty/sys/mman.h>
#include <uapi/err.h>

#include <imx-regs.h>
#include "caam.h"
#include "fsl_caam_internal.h"
#include "hwkey_keyslots.h"

#define TLOG_TAG "caam_drv"
#include <trusty_log.h>

#define SHA1_DIGEST_LEN 20
#define SHA256_DIGEST_LEN 32
#define FSL_CAAM_MP_PUBK_BYTES 64
#define PDB_MP_CSEL_SHIFT 17
#define PDB_MP_CSEL_WIDTH 4
#define PDB_MP_CSEL_P256 0x3UL << PDB_MP_CSEL_SHIFT /* P-256 */
#define PDB_MP_CSEL_P384 0x4UL << PDB_MP_CSEL_SHIFT /* P-384 */
#define PDB_MP_CSEL_P521 0x5UL << PDB_MP_CSEL_SHIFT /* P-521 */
#define ERR_BAD_LEN             (-32)

#define CACHE_ALIGN 64UL
#define ALIGN(x,y) (((x)+(y-1))&~(y-1))

static struct caam_job_rings* g_rings;
static struct caam_job* g_job;

const uint32_t rng_inst_dsc[] = {
        RNG_INST_DESC1, RNG_INST_DESC2, RNG_INST_DESC3,
        RNG_INST_DESC4, RNG_INST_DESC5, RNG_INST_DESC6,
        RNG_INST_DESC7, RNG_INST_DESC8, RNG_INST_DESC9};

/* AES ECB CBC descriptor template*/
static const uint32_t aes_decriptor_template_ecb_cbc[] = {
  /* 00 */ HEADER_COMMAND, /* HEADER */
  /* 01 */ 0x02000000, /* KEY */
  /* 02 */ 0x00000000, /* place: key address */
  /* 03 */ 0x12200010, /* LOAD 16 bytes of iv to Class 1 Context Register */
  /* 04 */ 0x00000000, /* place: iv address */
  /* 05 */ 0x23130000, /* FIFO LOAD Message via SGT */
  /* 06 */ 0x00000000, /* place: source address */
  /* 07 */ 0x61300000, /* FIFO STORE Message via SGT */
  /* 08 */ 0x00000000, /* place: destination address */
  /* 09 */ 0x82100000, /* OPERATION: AES Decrypt, AS = zeroes,*/
  /* 10 */ 0x52200010, /* STORE IV from Class 1 Context Register offset 0 bytes.*/
  /* 11 */ 0x00000000, /* place: iv address */
};

/* CAAM AES CTR mode*/
static const uint32_t aes_decriptor_template_ctr[] = {
  /* 00 */ HEADER_COMMAND, /* HEADER */
  /* 01 */ 0x02000000, /* KEY */
  /* 02 */ 0x00000000, /* place: key address */
  /* 03 */ 0x12201010, /* LOAD 16 bytes of CTR0 to Class 1 Context Register. Offset 16 bytes. */
  /* 04 */ 0x00000000, /* place: CTR0 address */

  /* 05 */ 0x82100000, /* OPERATION: AES CTR (de)crypt in Update mode */
  /* 06 */ 0x23130000, /* FIFO LOAD Message */
  /* 07 */ 0x00000000, /* place: source address */
  /* 08 */ 0x61300000, /* FIFO STORE Message */
  /* 09 */ 0x00000000, /* place: destination address */

  /* 10 */ 0xA2000001, /* JMP always to next command. Done checkpoint (wait for Class 1 Done) */
  /* 11 */ 0x10880004, /* LOAD Immediate to Clear Written Register. */
  /* 12 */ 0x08000004, /* value for Clear Written Register: C1D and C1DS bits are set */
  /* 13 */ 0x22930010, /* FIFO LOAD Message Immediate 16 bytes */
  /* 14 */ 0x00000000, /* all zeroes 0-3 */

  /* 15 */ 0x00000000, /* all zeroes 4-7 */
  /* 16 */ 0x00000000, /* all zeroes 8-11 */
  /* 17 */ 0x00000000, /* all zeroes 12-15 */
  /* 18 */ 0x60300010, /* FIFO STORE Message 16 bytes */
  /* 19 */ 0x00000000, /* place: nonce_last[] block address */

  /* 20 */ 0x82100000, /* OPERATION: AES CTR (de)crypt in Update mode */
  /* 21 */ 0x52201010, /* STORE 16 bytes of CTRi from Class 1 Context Register offset 16 bytes. */
  /* 22 */ 0x00000000, /* place: CTRi address */
};

/*AES GCM mode*/
static const uint32_t aes_decriptor_template_gcm[] = {
   /* 00 */ HEADER_COMMAND, /* HEADER */
   /* 01 */ 0x02000000, /* KEY */
   /* 02 */ 0x00000000, /* place: key address */

   /* 03 */ 0x82100900, /* OPERATION: AES GCM Encrypt Update */

   /* 04 */ 0x12200000, /* lOAD context to Class 1 context offset 0 tag */
   /* 05 */ 0x00000000, /* place: context address */

   /* 06 */ 0xA0000002, /* Jump to next 2 command */
   /* 07 */ 0x00000000, /* NULL */

   /* 08 */ 0xA0000004, /* Jump to next 4 command */
   /* 09 */ 0x00000000, /* NULL*/

   /* 10 */ 0xA0000002, /* Jump to next 2 command */
   /* 11 */ 0x00000000, /* NULL */

   /* 12 */ 0x00000000, /* NULL*/
   /* 13 */ 0x00000000, /* NULL*/

   /* 14 */ 0x52200000, /* STORE from Class 1 context to tag */
   /* 15 */ 0x00000000, /* place: context address */
};

/* DES EDE */
static const uint32_t des_decriptor_template_ede_cbc[] = {
  /* 00 */ HEADER_COMMAND, /* HEADER */
  /* 01 */ 0x02000000, /* KEY */
  /* 02 */ 0x00000000, /* place: key address */
  /* 03 */ 0x12200008, /* LOAD 8 bytes of iv to Class 1 Context Register */
  /* 04 */ 0x00000000, /* place: iv address */
  /* 05 */ 0x23130000, /* FIFO LOAD Message via SGT */
  /* 06 */ 0x00000000, /* place: SGT address */
  /* 07 */ 0x61300000, /* FIFO STORE Message via SGT */
  /* 08 */ 0x00000000, /* place: SGT address */
  /* 09 */ 0x82200000, /* OPERATION: DES Decrypt, AS = zeroes, AAI = zeroes (CTR) */
  /* 10 */ 0x52200008, /* STORE IV from Class 1 Context Register offset 0 bytes. */
  /* 11 */ 0x00000000, /* place: iv address */
};

static bool cipher_arg_is_valid(size_t len, const uint8_t* data_ptr) {
    if (len == 0 || data_ptr == NULL) {
        return false;
    }
    return true;
}

static int handle_sg_buffer(void *buf, size_t len, void **tmp_buf,
                            caam_sgt_entry_t **sg, uint32_t *sg_pa) {
    struct dma_pmem pmem[4];
    caam_sgt_entry_t *sg_ptr = NULL;
    void *buf_ptr = NULL;
    int i, entries;

    assert(*tmp_buf == NULL);
    assert(*sg == NULL);

    entries = prepare_dma(buf, len, DMA_FLAG_TO_DEVICE | DMA_FLAG_MULTI_PMEM, &pmem[0]);
    if ((pmem[0].paddr % CACHE_ALIGN) || (pmem[0].size % CACHE_ALIGN)) {
        /* allocate temp memory */
        buf_ptr = memalign(CACHE_ALIGN, len);
        if (!buf_ptr) {
            TLOGE("unable to allocate memory.\n");
            goto fail;
        }
        memcpy(buf_ptr, buf, len);

        entries = prepare_dma(buf_ptr, len, DMA_FLAG_TO_DEVICE | DMA_FLAG_MULTI_PMEM, &pmem[0]);
        if (entries == ERR_BAD_LEN) {
            TLOGE("input error: bad len.\n");
            goto fail;
        }
        *tmp_buf = buf_ptr;
    }

    // alloc sg structure
    sg_ptr = (caam_sgt_entry_t *)memalign(CACHE_ALIGN, entries * sizeof(caam_sgt_entry_t));
    memset(sg_ptr, 0, entries * sizeof(caam_sgt_entry_t));
    if (!sg_ptr) {
        TLOGE("unable to allocate memory.\n");
        goto fail;
    }
    *sg = sg_ptr;
    for(i = 0; i < entries - 1; i++) {
        sg_ptr[i].address_l = (uint32_t)pmem[i].paddr;
        sg_ptr[i].address_h = 0;
        sg_ptr[i].length = pmem[i].size;
    }
    sg_ptr[i].address_l = (uint32_t)pmem[i].paddr;
    sg_ptr[i].address_h = 0;
    sg_ptr[i].length =  pmem[i].size | 0x40000000u;

    entries = prepare_dma(sg_ptr, ALIGN(entries * sizeof(caam_sgt_entry_t), CACHE_ALIGN),
                         DMA_FLAG_TO_DEVICE | DMA_FLAG_MULTI_PMEM, &pmem[0]);
    if(entries == ERR_BAD_LEN){
        TLOGE("input error: bad len.\n");
        goto fail;
    }

    *sg_pa = (uint32_t)(pmem[0].paddr);
    return 0;

// on error
fail:
    if (*tmp_buf)
        free(*tmp_buf);
    if (*sg)
        free(*sg);

    return -1;
}

static int handle_buffer(void *buf, size_t len, void **tmp_buf, uint32_t *pa)
{
    struct dma_pmem pmem;
    int entry;
    void *buf_ptr;

    entry = prepare_dma(buf, len, DMA_FLAG_TO_DEVICE, &pmem);
    if (entry == ERR_BAD_LEN) {
        TLOGE("error: bad len.\n");
        return -1;;
    }

    if ((pmem.paddr % CACHE_ALIGN) || (pmem.size % CACHE_ALIGN)) {
        /* allocate temp memory */
        buf_ptr = memalign(CACHE_ALIGN, len);
        if (!buf_ptr) {
            TLOGE("unable to allocate memory.\n");
            return -1;;
        }
        memcpy(buf_ptr, buf, len);

        entry = prepare_dma(buf_ptr, ALIGN(len, CACHE_ALIGN), DMA_FLAG_TO_DEVICE, &pmem);
        if (entry == ERR_BAD_LEN) {
            TLOGE("error: bad len.\n");
            free(buf_ptr);
            return -1;
        }
        *tmp_buf = buf_ptr;
    }

    *pa = (uint32_t)(pmem.paddr);

    return 0;
}

#if !defined(MACH_IMX7) && !defined(MACH_IMX6)
static void caam_clk_get(void) {
    return;
}
#else /* !defined(MACH_IMX7) && !defined(MACH_IMX6) */
static void caam_clk_get(void) {
    uint32_t val;

    /* make sure clock is on */
    val = readl(ccm_base + CCM_CAAM_CCGR_OFFSET);
#if defined(MACH_IMX6)
    val |= (3 << 8) | (3 < 10) | (3 << 12);
#elif defined(MACH_IMX7)
    val = (3 << 0); /* Always enabled (for now) */
#else
#error Unsupported IMX architecture
#endif
    writel(val, ccm_base + CCM_CAAM_CCGR_OFFSET);
}
#endif

static void setup_job_rings(void) {
    int rc;
    struct dma_pmem pmem;

    /* Initialize job ring addresses */
    memset(g_rings, 0, sizeof(*g_rings));
    rc = prepare_dma(g_rings, sizeof(*g_rings), DMA_FLAG_TO_DEVICE, &pmem);
    if (rc != 1) {
        TLOGE("prepare_dma failed: %d\n", rc);
        abort();
    }

    /* Initialize job ring sizes */
    writel((uint32_t)pmem.paddr + offsetof(struct caam_job_rings, in),
           CAAM_IRBAR);  // input ring address
    writel((uint32_t)pmem.paddr + offsetof(struct caam_job_rings, out),
           CAAM_ORBAR);  // output ring address

    /* Initialize job ring sizes */
    writel(countof(g_rings->in), CAAM_IRSR);
    writel(countof(g_rings->in), CAAM_ORSR);
}

void run_job(struct caam_job* job) {
    int ret;
    uint32_t job_pa;
    struct dma_pmem pmem;

    /* prepare dma job */
    ret = prepare_dma(job->dsc, job->dsc_used * sizeof(uint32_t),
                      DMA_FLAG_TO_DEVICE, &pmem);
    assert(ret == 1);
    job_pa = (uint32_t)pmem.paddr;

    /* Add job to input ring */
    g_rings->out[0] = 0;
    g_rings->out[1] = 0;
    g_rings->in[0] = job_pa;

    ret = prepare_dma(g_rings, sizeof(*g_rings), DMA_FLAG_TO_DEVICE, &pmem);
    assert(ret == 1);

    /* get clock */
    caam_clk_get();

    /* start job */
    writel(1, CAAM_IRJAR);

    /* Wait for job ring to complete the job: 1 completed job expected */
    while (readl(CAAM_ORSFR) != 1)
        ;

    finish_dma(g_rings->out, sizeof(g_rings->out), DMA_FLAG_FROM_DEVICE);

    /* check that descriptor address is the one expected in the out ring */
    assert(g_rings->out[0] == job_pa);

    job->status = g_rings->out[1];

    /* remove job */
    writel(1, CAAM_ORJRR);
}

int init_caam_env(void) {
    caam_base = mmap(NULL, CAAM_REG_SIZE, PROT_READ | PROT_WRITE,
                     MMAP_FLAG_IO_HANDLE, CAAM_MMIO_ID, 0);
    if (caam_base == MAP_FAILED) {
        TLOGE("caam base mapping failed!\n");
        return ERR_GENERIC;
    }

    sram_base = mmap(NULL, CAAM_SEC_RAM_SIZE, PROT_READ | PROT_WRITE,
                     MMAP_FLAG_IO_HANDLE, CAAM_SEC_RAM_MMIO_ID, 0);
    if (sram_base == MAP_FAILED) {
        TLOGE("caam secure ram base mapping failed!\n");
        return ERR_GENERIC;
    }

#if defined(MACH_IMX7D)
    ccm_base = mmap(NULL, CCM_REG_SIZE, PROT_READ | PROT_WRITE,
                    MMAP_FLAG_IO_HANDLE, CCM_MMIO_ID, 0);
    if (ccm_base == MAP_FAILED) {
        TLOGE("ccm base mapping failed!\n");
        return ERR_GENERIC;
    }

    TLOGD("caam bases: %p, %p, %p\n", caam_base, sram_base, ccm_base);
#endif

    /* allocate rings */
    assert(sizeof(struct caam_job_rings) <= 16); /* TODO handle alignment */
    g_rings = memalign(16, sizeof(struct caam_job_rings));
    if (!g_rings) {
        TLOGE("out of memory allocating rings\n");
        return ERR_NO_MEMORY;
    }

    /* allocate jobs */
    g_job = memalign(MAX_DSC_NUM * sizeof(uint32_t), sizeof(struct caam_job));
    if (!g_job) {
        TLOGE("out of memory allocating job\n");
        return ERR_NO_MEMORY;
    }

#if defined(MACH_IMX8MQ) || defined(MACH_IMX8MM) || defined(MACH_IMX8MP) || defined(MACH_IMX8ULP)
    /* The JR0 is assigned to non-secure world by default in ATF, assign
     * it to secure world here. */
    uint32_t cfg_ms = 0;
    uint32_t cfg_ls = 0;

#ifdef MACH_IMX8ULP
    cfg_ms = 0x7UL << 0;  /* JRxDID_MS_PRIM_DID */
#else
    cfg_ms = 0x1UL << 0;  /* JRxDID_MS_PRIM_DID */
#endif
    cfg_ms |= (0x1UL << 4) | (0x1UL << 15); /* JRxDID_MS_PRIM_TZ | JRxDID_MS_TZ_OWN */
    cfg_ms |= (0x1UL << 16); /* JRxDID_MS_AMTD */
    cfg_ms |= (0x1UL << 19); /* JRxDID_MS_PRIM_ICID */
    cfg_ms |= (0x1UL << 31); /* JRxDID_MS_LDID */
    cfg_ms |= (0x1UL << 17); /* JRxDID_MS_LAMTD */

    writel(cfg_ms, CAAM_JR2MIDR);
    writel(cfg_ls, CAAM_JR2LIDR);
#endif
#ifdef MACH_IMX8Q
    /* imx8q caam init has been done by SECO. */
    /* Initialize job ring addresses */
    setup_job_rings();
#else
    caam_open();
#endif
#ifdef WITH_CAAM_SELF_TEST
    caam_test();
#endif

    return 0;
}

void caam_open(void) {
    uint32_t temp_reg;

    /* switch on CAAM clock */
    caam_clk_get();

    /* Initialize job ring addresses */
    setup_job_rings();

    /* HAB disables interrupts for JR0 so do the same here */
    temp_reg = readl(CAAM_JRCFGR2_LS) | JRCFG_LS_IMSK;
    writel(temp_reg, CAAM_JRCFGR2_LS);

    /* if RNG already instantiated then skip it */
    if ((readl(CAAM_RDSTA) & RDSTA_IF0) != RDSTA_IF0) {
        TLOGE("CAAM RNG should already be instantiated in SPL!\n");

        /* Enter TRNG Program mode */
        writel(RTMCTL_PGM, CAAM_RTMCTL);

        /* Set OSC_DIV field to TRNG */
        temp_reg = readl(CAAM_RTMCTL) | (RNG_TRIM_OSC_DIV << 2);
        writel(temp_reg, CAAM_RTMCTL);

        /* Set delay */
        writel(((RNG_TRIM_ENT_DLY << 16) | 0x09C4), CAAM_RTSDCTL);
        writel((RNG_TRIM_ENT_DLY >> 1), CAAM_RTFRQMIN);
        writel((RNG_TRIM_ENT_DLY << 4), CAAM_RTFRQMAX);

        /* Resume TRNG Run mode */
        temp_reg = readl(CAAM_RTMCTL) ^ RTMCTL_PGM;
        writel(temp_reg, CAAM_RTMCTL);

        temp_reg = readl(CAAM_RTMCTL) | RTMCTL_ERR;
        writel(temp_reg, CAAM_RTMCTL);

        uint32_t retry = 5;
        /* Some device like imx8m may failed init. Need retry. */
        while (retry) {
            retry--;
            /* init rng job */
            assert(sizeof(rng_inst_dsc) <= sizeof(g_job->dsc));
            memcpy(g_job->dsc, rng_inst_dsc, sizeof(rng_inst_dsc));
            g_job->dsc_used = countof(rng_inst_dsc);

            run_job(g_job);

            if (g_job->status & JOB_RING_STS) {
                TLOGE("job failed (0x%08x)\n", g_job->status);
                temp_reg = readl(CAAM_RTMCTL) | RTMCTL_ERR;
                writel(temp_reg, CAAM_RTMCTL);
            } else {
                break;
            }
        }

        /* ensure that the RNG was correctly instantiated */
        temp_reg = readl(CAAM_RDSTA);
        if (temp_reg != (RDSTA_IF0 | RDSTA_SKVN)) {
            TLOGE("Bad RNG state 0x%X\n", temp_reg);
            abort();
        }
    }

    return;
}

static uint32_t get_dma_address(uint8_t *address, uint32_t length)
{
    int ret;
    struct dma_pmem pmem;
    ret = prepare_dma((void*)address, length, DMA_FLAG_TO_DEVICE, &pmem);
    if (ret != 1) {
        return 0;
    }
    return (uint32_t)pmem.paddr;
}

uint32_t caam_decap_blob(const uint8_t* kmod,
                         size_t kmod_size,
                         uint8_t* plain,
                         const uint8_t* blob,
                         uint32_t size) {
    int ret;
    uint32_t kmod_pa;
    uint32_t blob_pa;
    uint32_t plain_pa;
    struct dma_pmem pmem;

    assert(size + CAAM_KB_HEADER_LEN < 0xFFFFu);
    assert(kmod_size == 16);

    ret = prepare_dma((void*)kmod, kmod_size, DMA_FLAG_TO_DEVICE, &pmem);
    if (ret != 1) {
        TLOGE("failed (%d) to prepare dma buffer\n", ret);
        return CAAM_FAILURE;
    }
    kmod_pa = (uint32_t)pmem.paddr;

    ret = prepare_dma((void*)blob, size + CAAM_KB_HEADER_LEN,
                      DMA_FLAG_TO_DEVICE, &pmem);
    if (ret != 1) {
        TLOGE("failed (%d) to prepare dma buffer\n", ret);
        return CAAM_FAILURE;
    }
    blob_pa = (uint32_t)pmem.paddr;

    ret = prepare_dma((void*)plain, size, DMA_FLAG_FROM_DEVICE, &pmem);
    if (ret != 1) {
        TLOGE("failed (%d) to prepare dma buffer\n", ret);
        return CAAM_FAILURE;
    }
    plain_pa = (uint32_t)pmem.paddr;

    g_job->dsc[0] = 0xB0800008;
    g_job->dsc[1] = 0x14400010;
    g_job->dsc[2] = kmod_pa;
    g_job->dsc[3] = 0xF0000000 | (0x0000ffff & (size + CAAM_KB_HEADER_LEN));
    g_job->dsc[4] = blob_pa;
    g_job->dsc[5] = 0xF8000000 | (0x0000ffff & (size));
    g_job->dsc[6] = plain_pa;
    g_job->dsc[7] = 0x860D0000;
    g_job->dsc_used = 8;

    run_job(g_job);

    if (g_job->status & JOB_RING_STS) {
        TLOGE("job failed (0x%08x)\n", g_job->status);
        return CAAM_FAILURE;
    }

    finish_dma(plain, size, DMA_FLAG_FROM_DEVICE);
    return CAAM_SUCCESS;
}

/* Use CAAM to encapsulate blob, all input/output buffer
 * address should be physical address.
 */
uint32_t caam_gen_blob_pa(uint32_t kmod_pa,
                          size_t kmod_size,
                          uint32_t plain_pa,
                          uint32_t blob_pa,
                          uint32_t size) {
    assert(size + CAAM_KB_HEADER_LEN < 0xFFFFu);
    assert(kmod_size == 16);

    g_job->dsc[0] = 0xB0800008;
    g_job->dsc[1] = 0x14400010;
    g_job->dsc[2] = kmod_pa;
    g_job->dsc[3] = 0xF0000000 | (0x0000ffff & (size));
    g_job->dsc[4] = plain_pa;
    g_job->dsc[5] = 0xF8000000 | (0x0000ffff & (size + CAAM_KB_HEADER_LEN));
    g_job->dsc[6] = blob_pa;
    g_job->dsc[7] = 0x870D0000;
    g_job->dsc_used = 8;

    run_job(g_job);

    if (g_job->status & JOB_RING_STS) {
        TLOGE("job failed (0x%08x)\n", g_job->status);
        return CAAM_FAILURE;
    }

    return CAAM_SUCCESS;
}

/* Use CAAM to encapsulate blob, all input/output buffer
 * address should be virtual address.
 */
uint32_t caam_gen_blob(const uint8_t* kmod,
                       size_t kmod_size,
                       const uint8_t* plain,
                       uint8_t* blob,
                       uint32_t size) {
    int ret;
    uint32_t kmod_pa;
    uint32_t blob_pa;
    uint32_t plain_pa;
    struct dma_pmem pmem;

    assert(size + CAAM_KB_HEADER_LEN < 0xFFFFu);
    assert(kmod_size == 16);

    ret = prepare_dma((void*)kmod, kmod_size, DMA_FLAG_TO_DEVICE, &pmem);
    if (ret != 1) {
        TLOGE("failed (%d) to prepare dma buffer\n", ret);
        return CAAM_FAILURE;
    }
    kmod_pa = (uint32_t)pmem.paddr;

    ret = prepare_dma((void*)plain, size, DMA_FLAG_TO_DEVICE, &pmem);
    if (ret != 1) {
        TLOGE("failed (%d) to prepare dma buffer\n", ret);
        return CAAM_FAILURE;
    }
    plain_pa = (uint32_t)pmem.paddr;

    ret = prepare_dma((void*)blob, size + CAAM_KB_HEADER_LEN,
                      DMA_FLAG_FROM_DEVICE, &pmem);
    if (ret != 1) {
        TLOGE("failed (%d) to prepare dma buffer\n", ret);
        return CAAM_FAILURE;
    }
    blob_pa = (uint32_t)pmem.paddr;

    if (caam_gen_blob_pa(kmod_pa, kmod_size, plain_pa, blob_pa, size)
                         != CAAM_SUCCESS) {
        return CAAM_FAILURE;
    }

    finish_dma(blob, size + CAAM_KB_HEADER_LEN, DMA_FLAG_FROM_DEVICE);
    return CAAM_SUCCESS;
}

uint32_t caam_aes_op(const uint8_t* key,
                     size_t key_size,
                     const uint8_t* in,
                     uint8_t* out,
                     size_t len,
                     bool enc) {
    int ret;
    uint32_t in_pa;
    uint32_t out_pa;
    uint32_t key_pa;
    struct dma_pmem pmem;

    assert(key_size == 16);
    assert(len <= 0xFFFFu);
    assert(len % 16 == 0);

    ret = prepare_dma((void*)key, key_size, DMA_FLAG_TO_DEVICE, &pmem);
    if (ret != 1) {
        TLOGE("failed (%d) to prepare dma buffer\n", ret);
        return CAAM_FAILURE;
    }
    key_pa = (uint32_t)pmem.paddr;

    ret = prepare_dma((void*)in, len, DMA_FLAG_TO_DEVICE, &pmem);
    if (ret != 1) {
        TLOGE("failed (%d) to prepare dma buffer\n", ret);
        return CAAM_FAILURE;
    }
    in_pa = (uint32_t)pmem.paddr;

    ret = prepare_dma(out, len, DMA_FLAG_FROM_DEVICE, &pmem);
    if (ret != 1) {
        TLOGE("failed (%d) to prepare dma buffer\n", ret);
        return CAAM_FAILURE;
    }
    out_pa = (uint32_t)pmem.paddr;

    /*
     * Now AES key use aeskey.
     * aeskey is derived from the first 16 bytes of RPMB key.
     */
    g_job->dsc[0] = 0xb0800008;
    g_job->dsc[1] = 0x02000010;
    g_job->dsc[2] = key_pa;
    g_job->dsc[3] = enc ? 0x8210020D : 0x8210020C;
    g_job->dsc[4] = 0x22120000 | (0x0000ffff & len);
    g_job->dsc[5] = in_pa;
    g_job->dsc[6] = 0x60300000 | (0x0000ffff & len);
    g_job->dsc[7] = out_pa;
    g_job->dsc_used = 8;

    run_job(g_job);

    if (g_job->status & JOB_RING_STS) {
        TLOGE("job failed (0x%08x)\n", g_job->status);
        return CAAM_FAILURE;
    }

    finish_dma(out, len, DMA_FLAG_FROM_DEVICE);
    return CAAM_SUCCESS;
}

uint32_t caam_hwrng(uint8_t* out, uint32_t len) {
    int ret;
    struct dma_pmem pmem;

    while (len) {
        ret = prepare_dma(out, len,
                          DMA_FLAG_FROM_DEVICE | DMA_FLAG_ALLOW_PARTIAL, &pmem);
        if (ret != 1) {
            TLOGE("failed (%d) to prepare dma buffer\n", ret);
            return CAAM_FAILURE;
        }

        if (caam_hwrng_pa(pmem.paddr, pmem.size) != CAAM_SUCCESS)
            return CAAM_FAILURE;

        finish_dma(out, pmem.size, DMA_FLAG_FROM_DEVICE);

        len -= pmem.size;
        out += pmem.size;
    }

    return CAAM_SUCCESS;
}

/* Generate "len" length rng and put it to "buf_pa". The buf_pa should
 * be physical address.
 * */
uint32_t caam_hwrng_pa(uint32_t buf_pa, uint32_t len)
{
        g_job->dsc[0] = 0xB0800004;
        g_job->dsc[1] = 0x82500002;
        g_job->dsc[2] = 0x60340000 | (0x0000ffff & len);
        g_job->dsc[3] = (uint32_t)buf_pa;
        g_job->dsc_used = 4;
        run_job(g_job);

        if (g_job->status & JOB_RING_STS) {
            TLOGE("job failed (0x%08x)\n", g_job->status);
            return CAAM_FAILURE;
        }

    return CAAM_SUCCESS;
}

void caam_get_keybox(struct keyslot_package *kbox) {

    /* sram_base points to device memory which is mapped with mmap(),
     * data fault may happen when use "ldur" to access such memory
     * after 64bit userspace is enabled. Make a memcpy here to bypass
     * this issue.
     */
    memcpy(kbox, sram_base, sizeof(struct keyslot_package));
    return;
}

/* support SHA1 and SHA256 calculation, both input/output address should
 * be physical address.
 */
uint32_t caam_hash_pa(uint32_t in_pa, uint32_t out_pa,
                      uint32_t len, enum hash_algo algo) {
    /* construct job descriptor */
    if (len < 0xffff) {
        g_job->dsc[0] = 0xB0800006;

        if (algo == SHA1)
            g_job->dsc[1] = 0x8441000D;
        else
            g_job->dsc[1] = 0x8443000D;

        g_job->dsc[2] = 0x24140000 | (0x0000ffff & len);
        g_job->dsc[3] = in_pa;

        if (algo == SHA1)
            g_job->dsc[4] = 0x54200000 | 20;
        else
            g_job->dsc[4] = 0x54200000 | 32;

        g_job->dsc[5] = out_pa;
        g_job->dsc_used = 6;
    } else {
        g_job->dsc[0] = 0xB0800007;

        if (algo == SHA1)
            g_job->dsc[1] = 0x8441000D;
        else
            g_job->dsc[1] = 0x8443000D;

        g_job->dsc[2] = 0x24540000;
        g_job->dsc[3] = in_pa;
        g_job->dsc[4] = len;

        if (algo == SHA1)
            g_job->dsc[5] = 0x54200000 | 20;
        else
            g_job->dsc[5] = 0x54200000 | 32;

        g_job->dsc[6] = out_pa;
        g_job->dsc_used = 7;
    }

    run_job(g_job);

    if (g_job->status & JOB_RING_STS) {
        TLOGE("job failed (0x%08x)\n", g_job->status);
        return CAAM_FAILURE;
    }

    return CAAM_SUCCESS;
}

/* support SHA1 and SHA256 calculation, both input/output address should
 * be virtual address.
 */
uint32_t caam_hash(uint32_t in, uint32_t out,
                   uint32_t len, enum hash_algo algo) {
    int ret;
    uint32_t in_pa;
    uint32_t out_pa;
    struct dma_pmem pmem;

    /* prepare dma and get input physical address */
    ret = prepare_dma((void*)(unsigned long)in, len, DMA_FLAG_TO_DEVICE, &pmem);
    if (ret != 1) {
        TLOGE("failed (%d) to prepare dma buffer\n", ret);
        return CAAM_FAILURE;
    }
    in_pa = (uint32_t)pmem.paddr;

    /* prepare dma and get output physical address */
    if (algo == SHA1)
        ret = prepare_dma((void *)(unsigned long)out, SHA1_DIGEST_LEN,
                          DMA_FLAG_FROM_DEVICE, &pmem);
    else if (algo == SHA256)
        ret = prepare_dma((void *)(unsigned long)out, SHA256_DIGEST_LEN,
                          DMA_FLAG_FROM_DEVICE, &pmem);
    else {
        TLOGE("unsupported hash algorithm!\n");
        return CAAM_FAILURE;
    }
    if (ret != 1) {
        TLOGE("failed (%d) to prepare dma buffer\n", ret);
        return CAAM_FAILURE;
    }
    out_pa = (uint32_t)pmem.paddr;

    /* hash calculation */
    if (caam_hash_pa(in_pa, out_pa, len, algo) != CAAM_SUCCESS)
        return CAAM_FAILURE;

    if (algo == SHA1)
        finish_dma((void *)(unsigned long)out, SHA1_DIGEST_LEN, DMA_FLAG_FROM_DEVICE);
    else if (algo == SHA256)
        finish_dma((void *)(unsigned long)out, SHA256_DIGEST_LEN, DMA_FLAG_FROM_DEVICE);
    else {
        TLOGE("unsupported hash algorithm!\n");
        return CAAM_FAILURE;
    }

    return CAAM_SUCCESS;
}

uint32_t caam_gen_kdfv1_root_key(uint8_t* out, uint32_t size) {
    int ret;
    uint32_t pa;
    struct dma_pmem pmem;

    assert(size == 32);

    ret = prepare_dma((void*)(unsigned long)out, size, DMA_FLAG_FROM_DEVICE, &pmem);
    if (ret != 1) {
        TLOGE("failed (%d) to prepare dma buffer\n", ret);
        return CAAM_FAILURE;
    }
    pa = (uint32_t)pmem.paddr;

    /*
     * This sequence uses caam blob generation protocol in
     * master key verification mode to generate unique for device
     * persistent 256-bit sequence that we will be using a root key
     * for our key derivation function v1. This is the only known way
     * on this platform of producing persistent unique device key that
     * does not require persistent storage. Dsc[2..5] effectively contains
     * 16 bytes of randomly generated salt that gets mixed (among other
     * things) with device master key to produce result.
     */
    g_job->dsc[0] = 0xB080000B;
    g_job->dsc[1] = 0x14C00010;
    g_job->dsc[2] = 0x7083A393; /* salt word 0 */
    g_job->dsc[3] = 0x2CC0C9F7; /* salt word 1 */
    g_job->dsc[4] = 0xFC5D2FC0; /* salt word 2 */
    g_job->dsc[5] = 0x2C4B04E7; /* salt word 3 */
    g_job->dsc[6] = 0xF0000000;
    g_job->dsc[7] = 0;
    g_job->dsc[8] = 0xF8000030;
    g_job->dsc[9] = pa;
    g_job->dsc[10] = 0x870D0002;
    g_job->dsc_used = 11;

    run_job(g_job);

    if (g_job->status & JOB_RING_STS) {
        TLOGE("job failed (0x%08x)\n", g_job->status);
        return CAAM_FAILURE;
    }

    finish_dma(out, size, DMA_FLAG_FROM_DEVICE);
    return CAAM_SUCCESS;
}

uint32_t caam_gen_bkek_key_pa(uint32_t kmod, uint32_t out, uint32_t size) {
    assert(size == 32);

    g_job->dsc[0] = 0xB0800006;
    g_job->dsc[1] = 0x14400010;
    g_job->dsc[2] = kmod;
    g_job->dsc[3] = 0xF8000020;
    g_job->dsc[4] = out;
    g_job->dsc[5] = 0x870D0002;
    g_job->dsc_used = 6;

    run_job(g_job);
    if (g_job->status & JOB_RING_STS) {
        TLOGE("job failed (0x%08x)\n", g_job->status);
        return CAAM_FAILURE;
    }

    finish_dma((void *)(unsigned long)out, size, DMA_FLAG_FROM_DEVICE);
    return CAAM_SUCCESS;
}

uint32_t caam_gen_bkek_key(const uint8_t* kmod, uint32_t kmod_size,
                           uint32_t out, uint32_t size) {
    int ret;
    uint32_t pa;
    uint32_t pa_keymod;
    struct dma_pmem pmem;

    assert(size == 32);

    ret = prepare_dma((void*)(unsigned long)out, size, DMA_FLAG_FROM_DEVICE, &pmem);
    if (ret != 1) {
        TLOGE("failed (%d) to prepare dma buffer\n", ret);
        return CAAM_FAILURE;
    }
    pa = (uint32_t)pmem.paddr;

    ret = prepare_dma((void*)kmod, kmod_size, DMA_FLAG_FROM_DEVICE, &pmem);
    if (ret != 1) {
        TLOGE("failed (%d) to prepare dma buffer\n", ret);
        return CAAM_FAILURE;
    }
    pa_keymod = (uint32_t)pmem.paddr;

    if (caam_gen_bkek_key_pa(pa_keymod, pa, size) != CAAM_SUCCESS)
        return CAAM_FAILURE;

    finish_dma((void *)(unsigned long)out, size, DMA_FLAG_FROM_DEVICE);
    return CAAM_SUCCESS;
}

uint32_t caam_gen_mppubk_pa(uint32_t out)
{
    g_job->dsc[0] = 0xB0840005;
#ifdef MACH_IMX8Q
    g_job->dsc[1] = PDB_MP_CSEL_P384;
#else
    g_job->dsc[1] = PDB_MP_CSEL_P256;
#endif
    g_job->dsc[2] = out;
    g_job->dsc[3] = 64;
    g_job->dsc[4] = 0x86140000;
    g_job->dsc_used = 5;

    run_job(g_job);

    if (g_job->status & JOB_RING_STS) {
        TLOGE("job failed (0x%08x)\n", g_job->status);
        return CAAM_FAILURE;
    }

    return CAAM_SUCCESS;
}

uint32_t caam_gen_mppriv(void)
{
    int ret;
    uint32_t pa;
    struct dma_pmem pmem;
    char passphrase[30] = "manufacturing protection";

    ret = prepare_dma((void*)passphrase, strlen(passphrase), DMA_FLAG_FROM_DEVICE, &pmem);
    if (ret != 1) {
        TLOGE("failed (%d) to prepare dma buffer\n", ret);
        return CAAM_FAILURE;
    }
    pa = (uint32_t)pmem.paddr;

    g_job->dsc[0] = 0xB0840005;
#ifdef MACH_IMX8Q
    g_job->dsc[1] = PDB_MP_CSEL_P384;
#else
    g_job->dsc[1] = PDB_MP_CSEL_P256;
#endif
    g_job->dsc[2] = pa;
    g_job->dsc[3] = strlen(passphrase);
    g_job->dsc[4] = 0x87140000;
    g_job->dsc_used = 5;

    run_job(g_job);

    if (g_job->status & JOB_RING_STS) {
        TLOGE("job failed (0x%08x)\n", g_job->status);
        return CAAM_FAILURE;
    }

    return CAAM_SUCCESS;
}

uint32_t caam_gen_mppubk(uint32_t out)
{
    int ret;
    uint32_t pa;
    struct dma_pmem pmem;

#if IMX8M_OPEN_MPPUBK_DEBUG
    caam_gen_mppriv();
#endif
    ret = prepare_dma((void*)(unsigned long)out, FSL_CAAM_MP_PUBK_BYTES, DMA_FLAG_FROM_DEVICE, &pmem);
    if (ret != 1) {
        TLOGE("failed (%d) to prepare dma buffer\n", ret);
        return CAAM_FAILURE;
    }
    pa = (uint32_t)pmem.paddr;

    if (caam_gen_mppubk_pa(pa) != CAAM_SUCCESS)
        return CAAM_FAILURE;

    finish_dma((void *)(unsigned long)out, FSL_CAAM_MP_PUBK_BYTES, DMA_FLAG_FROM_DEVICE);
    return CAAM_SUCCESS;
}

/* CAAM AES ECB mode */
int caam_aes_ecb_sg(uint32_t enc_flag,
                    uint32_t key,
                    uint32_t key_size,
                    uint32_t input_sg,
                    uint32_t output_sg,
                    uint32_t size) {
    uint32_t *descriptor = g_job->dsc;

    if (!((key_size == 16) || ((key_size == 24)) || ((key_size == 32)))) {
        TLOGE("invaild parameter!\n");
        return CAAM_FAILURE;
    }
    /* ECB mode, size must be non-zero 16-byte multiple */
    if (size % 16) {
        TLOGE("invaild parameter!\n");
        return CAAM_FAILURE;
    }

    memcpy(descriptor, aes_decriptor_template_ecb_cbc, sizeof(aes_decriptor_template_ecb_cbc));
    HEADER_SET_DESC_LEN(descriptor[0], 10);

    descriptor[1] |= (key_size & 0x3FF);
    descriptor[2] = key;
    /*ECB has no context, jump to current index + 2 = 6 (FIFO LOAD)*/
    descriptor[3] = 0xA0000002u;
    descriptor[5] |= (size & 0x0000FFFFu);
    descriptor[6] = input_sg;
    descriptor[7] |= (size & 0x0000FFFFu);
    descriptor[8] = output_sg;
    descriptor[9] |= ALGORITHM_OPERATION_CMD_AAI_ECB;
    if (CAAM_CIPHER_ENCRYPT == enc_flag)
        descriptor[9] |= CIPHER_ENCRYPT; /* add ENC bit to specify Encrypt OPERATION */

    g_job->dsc_used = 10;
    run_job(g_job);

    if (g_job->status & JOB_RING_STS) {
        TLOGE("job failed (0x%08x)\n", g_job->status);
        return CAAM_FAILURE;
    }
    return CAAM_SUCCESS;
}

/* CAAM AES ECB mode - virtual address*/
int caam_aes_ecb(uint32_t enc_flag,
                      const void * key,
                      size_t key_size,
                      const void * input_text,
                      size_t input_text_size,
                      void * output_text,
                      size_t output_text_size)
{
    caam_sgt_entry_t *input_text_sg = NULL, *output_text_sg = NULL;
    void *input_text_tmp = NULL, *output_text_tmp = NULL;
    void *key_tmp = NULL;
    uint32_t input_text_sg_pa, output_text_sg_pa, key_pa;
    int ret = -1;

    /* text in */
    if (!cipher_arg_is_valid(input_text_size, input_text)) {
        TLOGE("Missing input text!\n");
        goto exit;
    } else {
        ret = handle_sg_buffer((void *)input_text, input_text_size,
                               &input_text_tmp, &input_text_sg, &input_text_sg_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    /* text out */
    if (!cipher_arg_is_valid(output_text_size, output_text)) {
        TLOGE("Missing output text!\n");
        ret = -1;
        goto exit;
    } else {
        ret = handle_sg_buffer(output_text, output_text_size,
                               &output_text_tmp, &output_text_sg, &output_text_sg_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    /* key */
    if (!cipher_arg_is_valid(key_size, key)) {
        TLOGE("Missing key!\n");
        ret = -1;
        goto exit;
    } else {
        ret = handle_buffer((void *)key, key_size, &key_tmp, &key_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    // Invalidate cacheline for output buffer.
    if (output_text_tmp != NULL) {
        finish_dma(output_text_tmp, input_text_size, DMA_FLAG_FROM_DEVICE);
    } else
        finish_dma(output_text, input_text_size, DMA_FLAG_FROM_DEVICE);

    ret = caam_aes_ecb_sg(enc_flag, key_pa, key_size,
                          input_text_sg_pa, output_text_sg_pa, input_text_size);
    if (ret != CAAM_SUCCESS) {
        ret = -1;
        TLOGE("AES ECB operation failed!\n");
        goto exit;
    }

    // the input/output text size should be same.
    if (output_text_tmp != NULL) {
        finish_dma(output_text_tmp, input_text_size, DMA_FLAG_FROM_DEVICE);
        memcpy(output_text, output_text_tmp, input_text_size);
    } else
        finish_dma(output_text, input_text_size, DMA_FLAG_FROM_DEVICE);

    ret = 0;

exit:
    if (input_text_tmp)
        free(input_text_tmp);
    if (input_text_sg)
        free(input_text_sg);
    if (output_text_tmp)
        free(output_text_tmp);
    if (output_text_sg)
        free(output_text_sg);
    if (key_tmp)
        free(key_tmp);

    return ret;
}

/* CAAM AES CBC mode*/
int caam_aes_cbc_sg(uint32_t enc_flag,
                    uint32_t iv_pa,
                    uint32_t key,
                    uint32_t key_size,
                    uint32_t input_sg,
                    uint32_t output_sg,
                    uint32_t size) {
    uint32_t *descriptor = g_job->dsc;

    if (!((key_size == 16) || ((key_size == 24)) || ((key_size == 32)))) {
        TLOGE("invaild parameter!\n");
        return CAAM_FAILURE;
    }

    memcpy(descriptor, aes_decriptor_template_ecb_cbc, sizeof(aes_decriptor_template_ecb_cbc));
    HEADER_SET_DESC_LEN(descriptor[0], 12);

    descriptor[1] |= (key_size & 0x3FF);
    descriptor[2] = key;
    descriptor[4] = iv_pa;
    descriptor[5] |= (size & 0x0000FFFFu);
    descriptor[6] = input_sg;
    descriptor[7] |= (size & 0x0000FFFFu);
    descriptor[8] = output_sg;
    descriptor[9] |= ALGORITHM_OPERATION_CMD_AAI_CBC;
    if (CAAM_CIPHER_ENCRYPT == enc_flag)
        descriptor[9] |= CIPHER_ENCRYPT; /* add ENC bit to specify Encrypt OPERATION */
    descriptor[11] = iv_pa;

    g_job->dsc_used = 12;
    run_job(g_job);

    if (g_job->status & JOB_RING_STS) {
        TLOGE("job failed (0x%08x)\n", g_job->status);
        return CAAM_FAILURE;
    }
    return CAAM_SUCCESS;
}

/* CAAM AES CBC mode - virtual address*/
int caam_aes_cbc(uint32_t enc_flag,
                      const void *iv,
                      size_t iv_size,
                      const void *key,
                      size_t key_size,
                      const void *input_text,
                      size_t input_text_size,
                      void *output_text,
                      size_t output_text_size)
{
    caam_sgt_entry_t *input_text_sg = NULL, *output_text_sg = NULL;
    void *input_text_tmp = NULL, *output_text_tmp = NULL;
    void *iv_tmp = NULL, *key_tmp = NULL;
    uint32_t input_text_sg_pa, output_text_sg_pa, iv_pa, key_pa;
    int ret = -1;

    /* text in */
    if (!cipher_arg_is_valid(input_text_size, input_text)) {
        TLOGE("Missing input text!\n");
        goto exit;
    } else {
        ret = handle_sg_buffer((void *)input_text, input_text_size,
                               &input_text_tmp, &input_text_sg, &input_text_sg_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    /* text out */
    if (!cipher_arg_is_valid(output_text_size, output_text)) {
        TLOGE("Missing output text!\n");
        ret = -1;
        goto exit;
    } else {
        ret = handle_sg_buffer(output_text, output_text_size,
                               &output_text_tmp, &output_text_sg, &output_text_sg_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    /* iv */
    if (cipher_arg_is_valid(iv_size, iv)) {
        ret = handle_buffer((void *)iv, iv_size, &iv_tmp, &iv_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    /* key */
    if (!cipher_arg_is_valid(key_size, key)) {
        TLOGE("Missing key!\n");
        ret = -1;
        goto exit;
    } else {
        ret = handle_buffer((void *)key, key_size, &key_tmp, &key_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    // Invalidate cacheline for output buffer.
    if (output_text_tmp != NULL) {
        finish_dma(output_text_tmp, input_text_size, DMA_FLAG_FROM_DEVICE);
    } else
        finish_dma(output_text, input_text_size, DMA_FLAG_FROM_DEVICE);

    ret = caam_aes_cbc_sg(enc_flag, iv_pa, key_pa, key_size,
                          input_text_sg_pa, output_text_sg_pa, input_text_size);
    if (ret != CAAM_SUCCESS) {
        ret = -1;
        TLOGE("AES CBC operation failed!\n");
        goto exit;
    }

    // the input/output text size should be same.
    if (output_text_tmp != NULL) {
        finish_dma(output_text_tmp, input_text_size, DMA_FLAG_FROM_DEVICE);
        memcpy(output_text, output_text_tmp, input_text_size);
    } else
        finish_dma(output_text, input_text_size, DMA_FLAG_FROM_DEVICE);

    ret = 0;

exit:
    if (input_text_tmp)
        free(input_text_tmp);
    if (input_text_sg)
        free(input_text_sg);
    if (output_text_tmp)
        free(output_text_tmp);
    if (output_text_sg)
        free(output_text_sg);
    if (iv_tmp)
        free(iv_tmp);
    if (key_tmp)
        free(key_tmp);

    return ret;
}

/* CAAM AES CTR mode*/
int caam_aes_ctr_sg(uint32_t enc_flag,
                    uint32_t iv_pa,
                    uint32_t key,
                    uint32_t key_size,
                    uint32_t input_sg,
                    uint32_t output_sg,
                    uint32_t size,
                    uint32_t ecount_buf,
                    uint32_t num_left) {
    uint32_t *descriptor = g_job->dsc;

    if (!((key_size == 16) || ((key_size == 24)) || ((key_size == 32)))) {
        TLOGE("invaild parameter!\n");
        return CAAM_FAILURE;
    }
    memcpy(descriptor, aes_decriptor_template_ctr, sizeof(aes_decriptor_template_ctr));
    HEADER_SET_DESC_LEN(descriptor[0], 23);

    /* If the key is encrypted, this is the decrypted length of the key material only. */
    descriptor[1] |= (key_size & 0x3FF);
    descriptor[2] = key;
    /* descriptor[3] configures 16 bytes length for CTR0 in aes_ctr_decriptor_template */
    descriptor[4] = iv_pa;

    descriptor[6] |= (size & 0x0000FFFFu);
    descriptor[7] = input_sg;
    descriptor[8] |= (size & 0x0000FFFFu);
    descriptor[9] = output_sg;

    if ( num_left == 0 ) {
        descriptor[10] = 0xA000000B; /* jump to current index + 11 (=21) */
    } else {
        descriptor[5] |= 0x08u; /* finalize will not update the latest CTR*/
    }
    descriptor[19] = ecount_buf;
    descriptor[22] = iv_pa;
    /* read last CTRi from AES back to caller */
    g_job->dsc_used = 23;

    run_job(g_job);

    if (g_job->status & JOB_RING_STS) {
        TLOGE("job failed (0x%08x)\n", g_job->status);
        return CAAM_FAILURE;
    }

    return CAAM_SUCCESS;
}

/* CAAM AES CTR mode - virtual address*/
int caam_aes_ctr(uint32_t enc_flag,
                      const void *iv,
                      size_t iv_size,
                      const void *key,
                      size_t key_size,
                      const void *input_text,
                      size_t input_text_size,
                      void *output_text,
                      size_t output_text_size)
{
    caam_sgt_entry_t *input_text_sg = NULL, *output_text_sg = NULL;
    void *input_text_tmp = NULL, *output_text_tmp = NULL;
    void *iv_tmp = NULL, *key_tmp = NULL;
    uint32_t input_text_sg_pa, output_text_sg_pa, iv_pa, key_pa;
    int ret = -1;

    /* text in */
    if (!cipher_arg_is_valid(input_text_size, input_text)) {
        TLOGE("Missing input text!\n");
        goto exit;
    } else {
        ret = handle_sg_buffer((void *)input_text, input_text_size,
                               &input_text_tmp, &input_text_sg, &input_text_sg_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    /* text out */
    if (!cipher_arg_is_valid(output_text_size, output_text)) {
        TLOGE("Missing output text!\n");
        ret = -1;
        goto exit;
    } else {
        ret = handle_sg_buffer(output_text, output_text_size,
                               &output_text_tmp, &output_text_sg, &output_text_sg_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    /* iv */
    if (cipher_arg_is_valid(iv_size, iv)) {
        ret = handle_buffer((void *)iv, iv_size, &iv_tmp, &iv_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    /* key */
    if (!cipher_arg_is_valid(key_size, key)) {
        TLOGE("Missing key!\n");
        ret = -1;
        goto exit;
    } else {
        ret = handle_buffer((void *)key, key_size, &key_tmp, &key_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    // Invalidate cacheline for output buffer.
    if (output_text_tmp != NULL) {
        finish_dma(output_text_tmp, input_text_size, DMA_FLAG_FROM_DEVICE);
    } else
        finish_dma(output_text, input_text_size, DMA_FLAG_FROM_DEVICE);

    ret = caam_aes_ctr_sg(enc_flag, iv_pa, key_pa, key_size, input_text_sg_pa,
                          output_text_sg_pa, input_text_size, 0, 0);
    if (ret != CAAM_SUCCESS) {
        ret = -1;
        TLOGE("AES CTR operation failed!\n");
        goto exit;
    }

    // the input/output text size should be same.
    if (output_text_tmp != NULL) {
        finish_dma(output_text_tmp, input_text_size, DMA_FLAG_FROM_DEVICE);
        memcpy(output_text, output_text_tmp, input_text_size);
    } else
        finish_dma(output_text, input_text_size, DMA_FLAG_FROM_DEVICE);

    ret = 0;

exit:
    if (input_text_tmp)
        free(input_text_tmp);
    if (input_text_sg)
        free(input_text_sg);
    if (output_text_tmp)
        free(output_text_tmp);
    if (output_text_sg)
        free(output_text_sg);
    if (iv_tmp)
        free(iv_tmp);
    if (key_tmp)
        free(key_tmp);

    return ret;
}

/* CAAM AES GCM mode*/
uint32_t caam_aes_gcm_sg( uint32_t enc_flag,
                          uint32_t iv_pa,
                          uint32_t iv_size,
                          uint32_t key_pa,
                          uint32_t key_size,
                          uint32_t aad_sg_pa,
                          uint32_t aad_len,
                          uint32_t input_sg_pa,
                          uint32_t output_sg_pa,
                          uint32_t size,
                          uint32_t context_pa,
                          uint32_t context_size,
                          bool ctx_save_flag,
                          bool finialize_flag)
{
    uint32_t *descriptor = g_job->dsc;
    memcpy(descriptor, aes_decriptor_template_gcm, sizeof(aes_decriptor_template_gcm));

    /* key address and key size */
    descriptor[1] |= (key_size & 0x3FFu);
    descriptor[2] = key_pa;

    /* Encrypt/Decrypt */
    if ( CAAM_CIPHER_ENCRYPT == enc_flag ) {
        descriptor[3] |= CIPHER_ENCRYPT; /* ENC */
    } else {
        descriptor[3] |= 0x1 << 1; /* ICV check */
    }

    if( finialize_flag == 1 ) {
        descriptor[3] |= 0x2 << 2;
    }

    if( iv_size == 0 ) {
        descriptor[4] |= (context_size & 0xFFu);
        descriptor[5] = context_pa;
    } else {
        descriptor[4] = 0x22210000, /* FIFO LOAD IV (flush) */
        descriptor[4] |= (iv_size & 0xFFu);
        descriptor[5] = iv_pa;

        if ( size == 0  && aad_len == 0 ) {
            descriptor[4] |= 0x00020000u; /* LC1 */
        }
    }

    /* AAD address and size */
    if( aad_len ) {
        descriptor[6] = 0x23310000, /* FIFO LOAD AAD (flush) */
        descriptor[6] |= (aad_len & 0x0000FFFF);
        if (size == 0) {
            descriptor[6] |= 0x00020000u; /* LC1 */
        }
        descriptor[7] = aad_sg_pa; /* place: AAD address */
    }

    if(size || finialize_flag) {
        /* source address and size */
        descriptor[8] = 0x23110000, /* FIFO LOAD SGT message(flush last) */
        descriptor[8] |= (size & 0x0000FFFF);

        descriptor[9] = input_sg_pa;

        if (CAAM_CIPHER_DECRYPT == enc_flag) {
            descriptor[10] = 0x223b0000 | (context_size & 0xFFu);
            descriptor[11] = context_pa;
        } else
            descriptor[8] |= 0x00020000u; /* LC1 */

        descriptor[12] = 0x61300000, /* FIFO STORE SGT Message */
        /* destination address and size */
        descriptor[12] |= (size & 0x0000FFFF);

        descriptor[13] = output_sg_pa;
    }

    if ( ctx_save_flag ) {
        descriptor[14] |= (context_size & 0xFFu);
        descriptor[15] = context_pa;
        descriptor[0] = HEADER_COMMAND;
        HEADER_SET_DESC_LEN(descriptor[0], 16);
        g_job->dsc_used = 16;
    } else {
        descriptor[0] = HEADER_COMMAND;
        HEADER_SET_DESC_LEN(descriptor[0], 14);
        g_job->dsc_used = 14;
    }
    /* schedule the job */
    run_job(g_job);
    if (g_job->status & JOB_RING_STS) {
        TLOGE("job failed (0x%08x)\n", g_job->status);
        return CAAM_FAILURE;
    }
    return CAAM_SUCCESS;
}

/* CAAM AES GCM mode - virtual address*/
int caam_aes_gcm(uint32_t enc_flag,
                      const void * iv,
                      size_t iv_size,
                      const void * key,
                      size_t key_size,
                      const void * aad,
                      size_t aad_size,
                      const void * input_text,
                      size_t input_text_size,
                      void * output_text,
                      size_t output_text_size,
                      const void * tag_in,
                      size_t tag_in_size,
                      void * tag_out,
                      size_t tag_out_size)
{
    caam_sgt_entry_t *input_text_sg = NULL, *output_text_sg = NULL, *aad_sg = NULL;
    void *input_text_tmp = NULL, *output_text_tmp = NULL, *aad_tmp = NULL;
    void *iv_tmp = NULL, *key_tmp = NULL, *tag_in_tmp = NULL, *tag_out_tmp = NULL;
    uint32_t input_text_sg_pa, output_text_sg_pa, aad_sg_pa, iv_pa, key_pa, tag_in_pa, tag_out_pa;
    int ret = -1;

    /* text in */
    if (!cipher_arg_is_valid(input_text_size, input_text)) {
        TLOGE("Missing input text!\n");
        goto exit;
    } else {
        ret = handle_sg_buffer((void *)input_text, input_text_size,
                               &input_text_tmp, &input_text_sg, &input_text_sg_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    /* text out */
    if (!cipher_arg_is_valid(output_text_size, output_text)) {
        TLOGE("Missing output text!\n");
        ret = -1;
        goto exit;
    } else {
        ret = handle_sg_buffer(output_text, output_text_size,
                               &output_text_tmp, &output_text_sg, &output_text_sg_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    /* aad */
    if (cipher_arg_is_valid(aad_size, aad)) {
        ret = handle_sg_buffer((void *)aad, aad_size, &aad_tmp, &aad_sg, &aad_sg_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    /* iv */
    if (cipher_arg_is_valid(iv_size, iv)) {
        ret = handle_buffer((void *)iv, iv_size, &iv_tmp, &iv_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    /* key */
    if (!cipher_arg_is_valid(key_size, key)) {
        TLOGE("Missing key!\n");
        ret = -1;
        goto exit;
    } else {
        ret = handle_buffer((void *)key, key_size, &key_tmp, &key_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    /*
     * tag_in should be invalid and tag_out should be valid when encryption,
     * tag_in should be valid and tag_out should be invalid when decryption.*/
    if (enc_flag) {
        if (cipher_arg_is_valid(tag_in_size, tag_in)) {
            TLOGE("Input authentication tag set while encrypting in GCM mode\n");
            ret = -1;
            goto exit;
        }

        if (!cipher_arg_is_valid(tag_out_size, tag_out)) {
            TLOGE("Missing output authentication tag in GCM mode\n");
            ret = -1;
            goto exit;
        } else {
            ret = handle_buffer(tag_out, tag_out_size, &tag_out_tmp, &tag_out_pa);
            if (ret) {
                ret = -1;
                goto exit;
            }
        }

        // Invalidate cacheline for output buffer.
        if (output_text_tmp != NULL) {
            finish_dma(output_text_tmp, input_text_size, DMA_FLAG_FROM_DEVICE);
        } else
            finish_dma(output_text, input_text_size, DMA_FLAG_FROM_DEVICE);

        if (tag_out_tmp != NULL) {
            finish_dma(tag_out_tmp, tag_out_size, DMA_FLAG_FROM_DEVICE);
        } else
            finish_dma(tag_out, tag_out_size, DMA_FLAG_FROM_DEVICE);

        ret = caam_aes_gcm_sg(1, iv_pa, iv_size, key_pa, key_size, aad_sg_pa, aad_size,
                              input_text_sg_pa, output_text_sg_pa, input_text_size,
                              tag_out_pa, tag_out_size, 1, 1);
        if (ret != CAAM_SUCCESS) {
            ret = -1;
            TLOGE("AES GCM operation failed!\n");
            goto exit;
        }

        // flush dcache for tag_out buffer
        if (tag_out_tmp != NULL) {
            finish_dma(tag_out_tmp, tag_out_size, DMA_FLAG_FROM_DEVICE);
            memcpy(tag_out, tag_out_tmp, tag_out_size);
        } else
            finish_dma(tag_out, tag_out_size, DMA_FLAG_FROM_DEVICE);
    } else {
        if (!cipher_arg_is_valid(tag_in_size, tag_in)) {
            TLOGE("Missing input authentication tag in GCM mode\n");
            ret = -1;
            goto exit;
        } else {
            ret = handle_buffer((void *)tag_in, tag_in_size, &tag_in_tmp, &tag_in_pa);
            if (ret) {
                ret = -1;
                goto exit;
            }
        }

        if (cipher_arg_is_valid(tag_out_size, tag_out)) {
            TLOGE("output authentication tag set while encrypting in GCM mode\n");
            ret = -1;
            goto exit;
        }

        // Invalidate cacheline for output buffer.
        if (output_text_tmp != NULL) {
            finish_dma(output_text_tmp, input_text_size, DMA_FLAG_FROM_DEVICE);
        } else
            finish_dma(output_text, input_text_size, DMA_FLAG_FROM_DEVICE);

        ret = caam_aes_gcm_sg(0, iv_pa, iv_size, key_pa, key_size, aad_sg_pa, aad_size,
                              input_text_sg_pa, output_text_sg_pa, input_text_size,
                              tag_in_pa, tag_in_size, 0, 1);

        if (ret != CAAM_SUCCESS) {
            TLOGE("AES GCM operation failed!\n");
            ret = -1;
            goto exit;
        }
    }

    // the input/output text size should be same.
    if (output_text_tmp != NULL) {
        finish_dma(output_text_tmp, input_text_size, DMA_FLAG_FROM_DEVICE);
        memcpy(output_text, output_text_tmp, input_text_size);
    } else
        finish_dma(output_text, input_text_size, DMA_FLAG_FROM_DEVICE);

    ret = 0;

exit:
    if (input_text_tmp)
        free(input_text_tmp);
    if (input_text_sg)
        free(input_text_sg);
    if (output_text_tmp)
        free(output_text_tmp);
    if (output_text_sg)
        free(output_text_sg);
    if (aad_tmp)
        free(aad_tmp);
    if (aad_sg)
        free(aad_sg);
    if (iv_tmp)
        free(iv_tmp);
    if (key_tmp)
        free(key_tmp);
    if (tag_in_tmp)
        free(tag_in_tmp);
    if (tag_out_tmp)
        free(tag_out_tmp);

    return ret;
}

/* DES EDE ECB mode*/
uint32_t caam_tdes_ecb_sg( uint32_t enc_flag,
                           uint32_t key_pa,
                           uint32_t key_size,
                           uint32_t input_sg,
                           uint32_t output_sg,
                           uint32_t size ) {
    uint32_t *descriptor = g_job->dsc;

    memcpy(descriptor, des_decriptor_template_ede_cbc, sizeof(des_decriptor_template_ede_cbc));
    HEADER_SET_DESC_LEN(descriptor[0], 10);
    descriptor[1] |= key_size;
    descriptor[2] = key_pa;
    descriptor[3] = 0xA0000002u; /* ECB has no context, jump to current index + 2 = 5 (FIFO LOAD) */
    descriptor[5] |= (size & 0x0000FFFF);
    descriptor[6] = input_sg;
    descriptor[7] |= (size & 0x0000FFFFu);
    descriptor[8] = output_sg;
    descriptor[9] |= ALGORITHM_OPERATION_CMD_AAI_ECB; /* AAI = 20h */
    if (CAAM_CIPHER_ENCRYPT == enc_flag)
        descriptor[9] |= CIPHER_ENCRYPT; /*  add ENC bit to specify Encrypt OPERATION */

    descriptor[9] |= ALGORITHM_OPERATION_ALGSEL_3DES;    /* 3DES */

    g_job->dsc_used = 10;

    /* schedule the job */
    run_job(g_job);

    if (g_job->status & JOB_RING_STS) {
        TLOGE("job failed (0x%08x)\n", g_job->status);
        return CAAM_FAILURE;
    }
    return CAAM_SUCCESS;
}

/* CAAM DES EDE ECB mode - virtual address*/
int caam_tdes_ecb(uint32_t enc_flag,
                      const void * key,
                      size_t key_size,
                      const void * input_text,
                      size_t input_text_size,
                      void * output_text,
                      size_t output_text_size)
{
    caam_sgt_entry_t *input_text_sg = NULL, *output_text_sg = NULL;
    void *input_text_tmp = NULL, *output_text_tmp = NULL;
    void *key_tmp = NULL;
    uint32_t input_text_sg_pa, output_text_sg_pa, key_pa;
    int ret = -1;

    /* text in */
    if (!cipher_arg_is_valid(input_text_size, input_text)) {
        TLOGE("Missing input text!\n");
        goto exit;
    } else {
        ret = handle_sg_buffer((void *)input_text, input_text_size,
                               &input_text_tmp, &input_text_sg, &input_text_sg_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    /* text out */
    if (!cipher_arg_is_valid(output_text_size, output_text)) {
        TLOGE("Missing output text!\n");
        ret = -1;
        goto exit;
    } else {
        ret = handle_sg_buffer(output_text, output_text_size,
                               &output_text_tmp, &output_text_sg, &output_text_sg_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    /* key */
    if (!cipher_arg_is_valid(key_size, key)) {
        TLOGE("Missing key!\n");
        ret = -1;
        goto exit;
    } else {
        ret = handle_buffer((void *)key, key_size, &key_tmp, &key_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    // Invalidate cacheline for output buffer.
    if (output_text_tmp != NULL) {
        finish_dma(output_text_tmp, input_text_size, DMA_FLAG_FROM_DEVICE);
    } else
        finish_dma(output_text, input_text_size, DMA_FLAG_FROM_DEVICE);

    ret = caam_tdes_ecb_sg(enc_flag, key_pa, key_size,
                           input_text_sg_pa, output_text_sg_pa, input_text_size);
    if (ret != CAAM_SUCCESS) {
        ret = -1;
        TLOGE("DES EDE ECB operation failed!\n");
        goto exit;
    }

    // the input/output text size should be same.
    if (output_text_tmp != NULL) {
        finish_dma(output_text_tmp, input_text_size, DMA_FLAG_FROM_DEVICE);
        memcpy(output_text, output_text_tmp, input_text_size);
    } else
        finish_dma(output_text, input_text_size, DMA_FLAG_FROM_DEVICE);

    ret = 0;

exit:
    if (input_text_tmp)
        free(input_text_tmp);
    if (input_text_sg)
        free(input_text_sg);
    if (output_text_tmp)
        free(output_text_tmp);
    if (output_text_sg)
        free(output_text_sg);
    if (key_tmp)
        free(key_tmp);

    return ret;
}
/* DES EDE CBC mode*/
uint32_t caam_tdes_cbc_sg(uint32_t enc_flag,
                          uint32_t iv_pa,
                          uint32_t key_pa,
                          uint32_t key_size,
                          uint32_t input_sg,
                          uint32_t output_sg,
                          uint32_t size ) {
    uint32_t *descriptor = g_job->dsc;

    memcpy(descriptor, des_decriptor_template_ede_cbc, sizeof(des_decriptor_template_ede_cbc));
    HEADER_SET_DESC_LEN(descriptor[0], 12);
    descriptor[1] |= key_size;
    descriptor[2] = key_pa;
    descriptor[4] = iv_pa;
    descriptor[5] |= (size & 0x0000FFFFu);
    descriptor[6] = input_sg;
    descriptor[7] |= (size & 0x0000FFFFu);
    descriptor[8] = output_sg;
    descriptor[9] |= ALGORITHM_OPERATION_CMD_AAI_CBC; /* AAI = 20h */
    if (CAAM_CIPHER_ENCRYPT == enc_flag)
        descriptor[9] |= CIPHER_ENCRYPT; /*  add ENC bit to specify Encrypt OPERATION */
    descriptor[9] |= ALGORITHM_OPERATION_ALGSEL_3DES;    /* 3DES */
    descriptor[11] = iv_pa;
    g_job->dsc_used = 12;

    /* schedule the job */
    run_job(g_job);

    if (g_job->status & JOB_RING_STS) {
        TLOGE("job failed (0x%08x)\n", g_job->status);
        return CAAM_FAILURE;
    }
    return CAAM_SUCCESS;
}

/* CAAM DES EDE CBC mode - virtual address*/
int caam_tdes_cbc(uint32_t enc_flag,
                  const void *iv,
                  size_t iv_size,
                  const void *key,
                  size_t key_size,
                  const void *input_text,
                  size_t input_text_size,
                  void *output_text,
                  size_t output_text_size)
{
    caam_sgt_entry_t *input_text_sg = NULL, *output_text_sg = NULL;
    void *input_text_tmp = NULL, *output_text_tmp = NULL;
    void *iv_tmp = NULL, *key_tmp = NULL;
    uint32_t input_text_sg_pa, output_text_sg_pa, iv_pa, key_pa;
    int ret = -1;

    /* text in */
    if (!cipher_arg_is_valid(input_text_size, input_text)) {
        TLOGE("Missing input text!\n");
        goto exit;
    } else {
        ret = handle_sg_buffer((void *)input_text, input_text_size,
                               &input_text_tmp, &input_text_sg, &input_text_sg_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    /* text out */
    if (!cipher_arg_is_valid(output_text_size, output_text)) {
        TLOGE("Missing output text!\n");
        ret = -1;
        goto exit;
    } else {
        ret = handle_sg_buffer(output_text, output_text_size,
                               &output_text_tmp, &output_text_sg, &output_text_sg_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    /* iv */
    if (cipher_arg_is_valid(iv_size, iv)) {
        ret = handle_buffer((void *)iv, iv_size, &iv_tmp, &iv_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    /* key */
    if (!cipher_arg_is_valid(key_size, key)) {
        TLOGE("Missing key!\n");
        ret = -1;
        goto exit;
    } else {
        ret = handle_buffer((void *)key, key_size, &key_tmp, &key_pa);
        if (ret) {
            ret = -1;
            goto exit;
        }
    }

    // Invalidate cacheline for output buffer.
    if (output_text_tmp != NULL) {
        finish_dma(output_text_tmp, input_text_size, DMA_FLAG_FROM_DEVICE);
    } else
        finish_dma(output_text, input_text_size, DMA_FLAG_FROM_DEVICE);

    ret = caam_tdes_cbc_sg(enc_flag, iv_pa, key_pa, key_size,
                           input_text_sg_pa, output_text_sg_pa, input_text_size);
    if (ret != CAAM_SUCCESS) {
        ret = -1;
        TLOGE("DES EDE CBC operation failed!\n");
        goto exit;
    }

    // the input/output text size should be same.
    if (output_text_tmp != NULL) {
        finish_dma(output_text_tmp, input_text_size, DMA_FLAG_FROM_DEVICE);
        memcpy(output_text, output_text_tmp, input_text_size);
    } else
        finish_dma(output_text, input_text_size, DMA_FLAG_FROM_DEVICE);

    ret = 0;

exit:
    if (input_text_tmp)
        free(input_text_tmp);
    if (input_text_sg)
        free(input_text_sg);
    if (output_text_tmp)
        free(output_text_tmp);
    if (output_text_sg)
        free(output_text_sg);
    if (iv_tmp)
        free(iv_tmp);
    if (key_tmp)
        free(key_tmp);

    return ret;
}

#ifdef WITH_CAAM_SELF_TEST
/*
 * HWRNG
 */
static void caam_hwrng_test(void) {
    DECLARE_SG_SAFE_BUF(out1, 32);
    DECLARE_SG_SAFE_BUF(out2, 32);

    caam_hwrng(out1, sizeof(out1));
    caam_hwrng(out2, sizeof(out2));

    if (memcmp(out1, out2, sizeof(out1)) == 0)
        TLOGE("caam hwrng test FAILED!!!\n");
    else
        TLOGE("caam hwrng test PASS!!!\n");
}

/*
 * Blob
 */
static void caam_blob_test(void) {
    uint i = 0;
    DECLARE_SG_SAFE_BUF(keymd, 16);
    DECLARE_SG_SAFE_BUF(plain, 32);
    DECLARE_SG_SAFE_BUF(plain_bak, 32);
    DECLARE_SG_SAFE_BUF(blob, 128);

    /* generate random key mod */
    caam_hwrng(keymd, sizeof(keymd));

    /* build known input */
    for (i = 0; i < sizeof(plain); i++) {
        plain[i] = i + '0';
        plain_bak[i] = plain[i];
    }

    /* encap  blob */
    caam_gen_blob(keymd, 16, plain, blob, sizeof(plain));
    memset(plain, 0xff, sizeof(plain));

    /* decap blob */
    caam_decap_blob(keymd, 16, plain, blob, sizeof(plain));

    /* compare with original */
    if (memcmp(plain, plain_bak, sizeof(plain)))
        TLOGE("caam blob test FAILED!!!\n");
    else
        TLOGE("caam blob test PASS!!!\n");
}

/*
 *  AES
 */
static void caam_aes_test(void) {
    DECLARE_SG_SAFE_BUF(key, 16);
    DECLARE_SG_SAFE_BUF(buf1, 32);
    DECLARE_SG_SAFE_BUF(buf2, 32);
    DECLARE_SG_SAFE_BUF(buf3, 32);

    /* generate random key */
    caam_hwrng(key, sizeof(key));

    /* create input */
    for (uint i = 0; i < sizeof(buf1); i++) {
        buf1[i] = i + '0';
    }

    /* reset output */
    memset(buf2, 0x55, sizeof(buf2));
    memset(buf3, 0xAA, sizeof(buf3));

    /* encrypt same data twice */
    caam_aes_op(key, 16, buf1, buf2, sizeof(buf1), true);
    caam_aes_op(key, 16, buf1, buf3, sizeof(buf1), true);

    /* compare results */
    if (memcmp(buf2, buf3, sizeof(buf1)))
        TLOGE("caam AES enc test FAILED!!!\n");
    else
        TLOGE("caam AES enc test PASS!!!\n");

    /* decrypt res */
    caam_aes_op(key, 16, buf3, buf2, sizeof(buf3), false);

    /* compare with original */
    if (memcmp(buf1, buf2, sizeof(buf1)))
        TLOGE("caam AES enc test FAILED!!!\n");
    else
        TLOGE("caam AES enc test PASS!!!\n");
}

/*
 * HASH (SHA-1)
 */
static void caam_hash_test(void) {
    DECLARE_SG_SAFE_BUF(in, 32);
    DECLARE_SG_SAFE_BUF(hash1, 32);
    DECLARE_SG_SAFE_BUF(hash2, 32);

    /* generate input */
    for (uint i = 0; i < sizeof(in); i++) {
        in[i] = i + '1';
    }

    /* reset output */
    memset(hash1, 0x55, sizeof(hash1));
    memset(hash2, 0xAA, sizeof(hash2));

    /* invoke hash twice */
    caam_hash((uint32_t)(intptr_t)in, (uint32_t)(intptr_t)hash1, sizeof(in), SHA256);
    caam_hash((uint32_t)(intptr_t)in, (uint32_t)(intptr_t)hash2, sizeof(in), SHA256);

    /* compare results */
    if (memcmp(hash1, hash2, 32) != 0)
        TLOGE("caam hash test FAILED!!!\n");
    else
        TLOGE("caam hash test PASS!!!\n");
}

static void caam_kdfv1_root_key_test(void) {
    DECLARE_SG_SAFE_BUF(out1, 32);
    DECLARE_SG_SAFE_BUF(out2, 32);

    caam_gen_kdfv1_root_key(out1, 32);
    caam_gen_kdfv1_root_key(out2, 32);

    if (memcmp(out1, out2, 32) != 0)
        TLOGE("caam gen kdf root key test FAILED!!!\n");
    else
        TLOGE("caam gen kdf root key test PASS!!!\n");
}

static unsigned char aes_ecb_test_buf_plain[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

static unsigned char aes_ecb_test_key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static unsigned char aes_ecb_test_buf_cipher[16] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
};

void caam_aes_ecb_test(void) {
    void *in_buf = malloc(16);
    void *out_buf = malloc(16);
    void *key_buf = malloc(16);

    memcpy(in_buf, aes_ecb_test_buf_plain, 16);
    memcpy(key_buf, aes_ecb_test_key, 16);
    memset(out_buf, 0xff, 16);

    caam_aes_ecb(1, key_buf, 16, in_buf, 16, out_buf, 16);
    if (memcmp(out_buf, aes_ecb_test_buf_cipher, 16))
        TLOGE("AES ECB encrytion test failed!\n");
    else
        TLOGE("AES ECB encrytion test passed!\n");

    memset(out_buf, 0xff, 16);
    memcpy(in_buf, aes_ecb_test_buf_cipher, 16);
    caam_aes_ecb(0, key_buf, 16, in_buf, 16, out_buf, 16);
    if (memcmp(out_buf, aes_ecb_test_buf_plain, 16))
        TLOGE("AES ECB decrytion test failed!\n");
    else
        TLOGE("AES ECB decrytion test passed!\n");

    free(in_buf);
    free(out_buf);
    free(key_buf);
}

static  unsigned char aes_cbc_test_buf_cipher[16] = {
    0xe7, 0x0b, 0xcd, 0x62, 0xc5, 0x95, 0xdc, 0x1b,
    0x2b, 0x8c, 0x19, 0x7b, 0xb9, 0x1a, 0x74, 0x47
};
static  unsigned char aes_cbc_test_buf_plain[16] = {
    0x8d, 0x4c, 0x1c, 0xac, 0x27, 0x51, 0x1e, 0xe2,
    0xd8, 0x24, 0x09, 0xa7, 0xf3, 0x78, 0xe7, 0xe4
};
static unsigned char aes_cbc_test_key[24] = {
    0x68, 0x96, 0x92, 0x15, 0xec, 0x41, 0xe4, 0xdf,
    0x7d, 0x23, 0xde, 0x0e, 0x80, 0x6f, 0x45, 0x8f,
    0x52, 0xaf, 0xf4, 0x92, 0xbd, 0x7c, 0x52, 0x63
};

static unsigned char aes_cbc_test_iv[16] = {
    0xe6, 0x1d, 0x13, 0xdf, 0xbf, 0x05, 0x33, 0x28,
    0x9f, 0x0e, 0x79, 0x50, 0x20, 0x9d, 0xa4, 0x18
};

void caam_aes_cbc_test(void) {
    void *in_buf = memalign(64, 64);
    void *out_buf = memalign(64, 64);
    void *iv_buf = memalign(64, 16);
    void *key_buf = memalign(64, 24);

    memcpy(in_buf, aes_cbc_test_buf_plain, 16);
    memcpy(iv_buf, aes_cbc_test_iv, 16);
    memcpy(key_buf, aes_cbc_test_key, 24);
    memset(out_buf, 0xff, 16);

    caam_aes_cbc(1, iv_buf, 16, key_buf, 24, in_buf, 16, out_buf, 16);
    if (memcmp(out_buf, aes_cbc_test_buf_cipher, 16))
        TLOGE("AES CBC encrytion test failed!\n");
    else
        TLOGE("AES CBC encrytion test passed!\n");

    memset(out_buf, 0xff, 16);
    memcpy(in_buf, aes_cbc_test_buf_cipher, 16);
    caam_aes_cbc(0, iv_buf, 16, key_buf, 24, in_buf, 16, out_buf, 16);
    if (memcmp(out_buf, aes_cbc_test_buf_plain, 16))
        TLOGE("AES CBC decrytion test failed!\n");
    else
        TLOGE("AES CBC decrytion test passed!\n");

    free(in_buf);
    free(out_buf);
    free(iv_buf);
    free(key_buf);
}

static unsigned char aes_ctr_test_buf_plain[55] = {
    0x6d, 0x2c, 0x07, 0xe1, 0xfc, 0x86, 0xf9, 0x9c,
    0x6e, 0x2a, 0x8f, 0x65, 0x67, 0x82, 0x8b, 0x42,
    0x62, 0xa9, 0xc2, 0x3d, 0x0f, 0x3e, 0xd8, 0xab,
    0x32, 0x48, 0x22, 0x83, 0xc7, 0x97, 0x96, 0xf0,
    0xad, 0xba, 0x1b, 0xcd, 0x37, 0x36, 0x08, 0x49,
    0x96, 0x45, 0x2a, 0x91, 0x7f, 0xae, 0x98, 0x00,
    0x5a, 0xeb, 0xe6, 0x1f, 0x9e, 0x91, 0xc3
};
static unsigned char aes_ctr_test_key[16] = {
    0x47, 0x13, 0xa7, 0xb2, 0xf9, 0x3e, 0xfe, 0x80,
    0x9b, 0x42, 0xec, 0xc4, 0x52, 0x13, 0xef, 0x9f
};
static unsigned char aes_ctr_test_iv[16] = {
    0xeb, 0xfa, 0x19, 0xb0, 0xeb, 0xf3, 0xd5, 0x7f,
    0xea, 0xbd, 0x4c, 0x4b, 0xd0, 0x4b, 0xea, 0x01
};
static unsigned char aes_ctr_test_buf_cipher[55] = {
    0x34, 0x5d, 0xeb, 0x1d, 0x67, 0xb9, 0x5e, 0x60,
    0x0e, 0x05, 0xca, 0xd4, 0xc3, 0x2e, 0xc3, 0x81,
    0xaa, 0xdb, 0x3e, 0x2c, 0x1e, 0xc7, 0xe0, 0xfb,
    0x95, 0x6d, 0xc3, 0x8e, 0x68, 0x60, 0xcf, 0x05,
    0x53, 0x53, 0x55, 0x66, 0xe1, 0xb1, 0x2f, 0xa9,
    0xf8, 0x7d, 0x29, 0x26, 0x6c, 0xa2, 0x6d, 0xf4,
    0x27, 0x23, 0x3d, 0xf0, 0x35, 0xdf, 0x28
};

void caam_aes_ctr_test(void) {
    void *in_buf = memalign(64, 55);
    void *out_buf = memalign(64, 55);
    void *iv_buf = memalign(64, 16);
    void *key_buf = memalign(64, 16);

    memcpy(in_buf, aes_ctr_test_buf_plain, 55);
    memcpy(iv_buf, aes_ctr_test_iv, 16);
    memcpy(key_buf, aes_ctr_test_key, 16);
    memset(out_buf, 0xff, 55);

    caam_aes_ctr(1, iv_buf, 16, key_buf, 16, in_buf, 55, out_buf, 55);
    if (memcmp(out_buf, aes_ctr_test_buf_cipher, 55))
        TLOGE("AES CTR encrytion test failed!\n");
    else
        TLOGE("AES CTR encrytion test passed!\n");

    memset(out_buf, 0xff, 55);
    memcpy(in_buf, aes_ctr_test_buf_plain, 16);
    caam_aes_ctr(0, iv_buf, 16, key_buf, 16, in_buf, 55, out_buf, 55);
    if (memcmp(out_buf, aes_ctr_test_buf_cipher, 55))
        TLOGE("AES CTR decrytion test failed!\n");
    else
        TLOGE("AES CTR decrytion test passed!\n");

    free(in_buf);
    free(out_buf);
    free(iv_buf);
    free(key_buf);
}

static  unsigned char aes_gcm_test_buf_plain[33] =
{
    0xcf, 0x77, 0x6d, 0xed, 0xf5, 0x3a, 0x82, 0x8d,
    0x51, 0xa0, 0x07, 0x3d, 0xb3, 0xef, 0x0d, 0xd1,
    0xee, 0x19, 0xe2, 0xe9, 0xe2, 0x43, 0xce, 0x97,
    0xe9, 0x58, 0x41, 0xbb, 0x9a, 0xd4, 0xe3, 0xff,
    0x52
};
static unsigned char aes_gcm_test_buf_key[24] =
{
    0x21, 0x33, 0x9f, 0xc1, 0xd0, 0x11, 0xab, 0xca,
    0x65, 0xd5, 0x0c, 0xe2, 0x36, 0x52, 0x30, 0x60,
    0x3f, 0xd4, 0x7d, 0x07, 0xe8, 0x83, 0x0f, 0x6e
};
static unsigned char aes_gcm_test_buf_aad[31] =
{
    0x04, 0xcd, 0xc1, 0xd8, 0x40, 0xc1, 0x7d, 0xcf,
    0xcc, 0xf7, 0x8b, 0x3d, 0x79, 0x24, 0x63, 0x74,
    0x0c, 0xe0, 0xbf, 0xdc, 0x16, 0x7b, 0x98, 0xa6,
    0x32, 0xe1, 0x44, 0xca, 0xfe, 0x96, 0x63
};
static unsigned char aes_gcm_test_buf_iv[12] =
{
    0xd5, 0xfb, 0x14, 0x69, 0xa8, 0xd8, 0x1d, 0xd7,
    0x52, 0x86, 0xa4, 0x18
};

static  unsigned char aes_gcm_test_buf_cipher[33] =
{
    0x3a, 0x0d, 0x48, 0x27, 0x81, 0x11, 0xd3, 0x29,
    0x6b, 0xc6, 0x63, 0xdf, 0x8a, 0x5d, 0xbe, 0xb2,
    0x47, 0x4e, 0xa4, 0x7f, 0xd8, 0x5b, 0x60, 0x8f,
    0x8d, 0x93, 0x75, 0xd9, 0xdc, 0xf7, 0xde, 0x14,
    0x13
};
void caam_aes_gcm_test(void)
{
    void *in_buf = memalign(64, 64);
    void *out_buf = memalign(64, 64);
    void *iv_buf = memalign(64, 12);
    void *test_key = memalign(64, 24);
    void *aad_buf = memalign(64, 64);
    void *context_buf = memalign(64, 64);

    memcpy(in_buf, aes_gcm_test_buf_plain, 33);
    memcpy(iv_buf, aes_gcm_test_buf_iv, 12);
    memcpy(test_key, aes_gcm_test_buf_key, 24);
    memcpy(aad_buf, aes_gcm_test_buf_aad, 31);

    memset(out_buf, 0xff, 33);
    memset(context_buf, 0xff, 64);

    caam_aes_gcm(1, iv_buf, 12, test_key, 24, aad_buf, 31, in_buf, 33, out_buf, 33, NULL, 0, context_buf, 16);
    if (memcmp(out_buf, aes_gcm_test_buf_cipher, 33))
        TLOGE("AES GCM encryption test failed!\n");
    else
        TLOGE("AES GCM encryption test passed!\n");

    memset(out_buf, 0xff, 64);
    memcpy(in_buf, aes_gcm_test_buf_cipher, 33);
    caam_aes_gcm(0, iv_buf, 12, test_key, 24, aad_buf, 31, in_buf, 33, out_buf, 33, context_buf, 16, NULL, 0);

    if (memcmp(out_buf, aes_gcm_test_buf_plain, 33))
        TLOGE("AES GCM decryption test failed!\n");
    else
        TLOGE("AES GCM decryption test passed!\n");

    free(in_buf);
    free(out_buf);
    free(iv_buf);
    free(test_key);
    free(aad_buf);
    free(context_buf);

}

static  unsigned char des_ede3_ecb_test_buf_plain[8] = {
    0x73, 0x6f, 0x6d, 0x65, 0x64, 0x61, 0x74, 0x61
};
static unsigned char des_ede3_ecb_test_key[24] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};
static unsigned char des_ede3_ecb_test_buf_cipher[8] = {
    0x18, 0xd7, 0x48, 0xe5, 0x63, 0x62, 0x05, 0x72
};

void caam_tdes_ecb_test(void) {
    void *in_buf = malloc(8);
    void *out_buf = malloc(8);
    void *key_buf = malloc(24);

    memcpy(in_buf, des_ede3_ecb_test_buf_plain, 8);
    memcpy(key_buf, des_ede3_ecb_test_key, 24);
    memset(out_buf, 0xff, 8);

    caam_tdes_ecb(1, key_buf, 24, in_buf, 8, out_buf, 8);
    if (memcmp(out_buf, des_ede3_ecb_test_buf_cipher, 8))
        TLOGE("DES EDE ECB encrytion test failed!\n");
    else
        TLOGE("DES EDE ECB encrytion test passed!\n");

    memset(out_buf, 0xff, 8);
    memcpy(in_buf, des_ede3_ecb_test_buf_cipher, 8);
    caam_tdes_ecb(0, key_buf, 24, in_buf, 8, out_buf, 8);
    if (memcmp(out_buf, des_ede3_ecb_test_buf_plain, 8))
        TLOGE("DES EDE ECB decrytion test failed!\n");
    else
        TLOGE("DES EDE ECB decrytion test passed!\n");

    free(in_buf);
    free(out_buf);
    free(key_buf);
}

static  unsigned char des3_ede_cbc_test_buf_plain[128] =
{
    0x6f, 0x54, 0x20, 0x6f, 0x61, 0x4d, 0x79, 0x6e,
    0x53, 0x20, 0x63, 0x65, 0x65, 0x72, 0x73, 0x74,
    0x54, 0x20, 0x6f, 0x6f, 0x4d, 0x20, 0x6e, 0x61,
    0x20, 0x79, 0x65, 0x53, 0x72, 0x63, 0x74, 0x65,
    0x20, 0x73, 0x6f, 0x54, 0x20, 0x6f, 0x61, 0x4d,
    0x79, 0x6e, 0x53, 0x20, 0x63, 0x65, 0x65, 0x72,
    0x73, 0x74, 0x54, 0x20, 0x6f, 0x6f, 0x4d, 0x20,
    0x6e, 0x61, 0x20, 0x79, 0x65, 0x53, 0x72, 0x63,
    0x74, 0x65, 0x20, 0x73, 0x6f, 0x54, 0x20, 0x6f,
    0x61, 0x4d, 0x79, 0x6e, 0x53, 0x20, 0x63, 0x65,
    0x65, 0x72, 0x73, 0x74, 0x54, 0x20, 0x6f, 0x6f,
    0x4d, 0x20, 0x6e, 0x61, 0x20, 0x79, 0x65, 0x53,
    0x72, 0x63, 0x74, 0x65, 0x20, 0x73, 0x6f, 0x54,
    0x20, 0x6f, 0x61, 0x4d, 0x79, 0x6e, 0x53, 0x20,
    0x63, 0x65, 0x65, 0x72, 0x73, 0x74, 0x54, 0x20,
    0x6f, 0x6f, 0x4d, 0x20, 0x6e, 0x61, 0x0a, 0x79
};
static unsigned char des3_ede_cbc_test_key[24] =
{
    0xE9, 0xC0, 0xFF, 0x2E, 0x76, 0x0B, 0x64, 0x24,
    0x44, 0x4D, 0x99, 0x5A, 0x12, 0xD6, 0x40, 0xC0,
    0xEA, 0xC2, 0x84, 0xE8, 0x14, 0x95, 0xDB, 0xE8
};
static unsigned char des3_ede_cbc_test_iv[8] =
{
    0x7D, 0x33, 0x88, 0x93, 0x0F, 0x93, 0xB2, 0x42
};
static  unsigned char des3_ede_cbc_test_buf_cipher[128] =
{
    0x0e, 0x2d, 0xb6, 0x97, 0x3c, 0x56, 0x33, 0xf4,
    0x67, 0x17, 0x21, 0xc7, 0x6e, 0x8a, 0xd5, 0x49,
    0x74, 0xb3, 0x49, 0x05, 0xc5, 0x1c, 0xd0, 0xed,
    0x12, 0x56, 0x5c, 0x53, 0x96, 0xb6, 0x00, 0x7d,
    0x90, 0x48, 0xfc, 0xf5, 0x8d, 0x29, 0x39, 0xcc,
    0x8a, 0xd5, 0x35, 0x18, 0x36, 0x23, 0x4e, 0xd7,
    0x76, 0xd1, 0xda, 0x0c, 0x94, 0x67, 0xbb, 0x04,
    0x8b, 0xf2, 0x03, 0x6c, 0xa8, 0xcf, 0xb6, 0xea,
    0x22, 0x64, 0x47, 0xaa, 0x8f, 0x75, 0x13, 0xbf,
    0x9f, 0xc2, 0xc3, 0xf0, 0xc9, 0x56, 0xc5, 0x7a,
    0x71, 0x63, 0x2e, 0x89, 0x7b, 0x1e, 0x12, 0xca,
    0xe2, 0x5f, 0xaf, 0xd8, 0xa4, 0xf8, 0xc9, 0x7a,
    0xd6, 0xf9, 0x21, 0x31, 0x62, 0x44, 0x45, 0xa6,
    0xd6, 0xbc, 0x5a, 0xd3, 0x2d, 0x54, 0x43, 0xcc,
    0x9d, 0xde, 0xa5, 0x70, 0xe9, 0x42, 0x45, 0x8a,
    0x6b, 0xfa, 0xb1, 0x91, 0x13, 0xb0, 0xd9, 0x19
};

void caam_tdes_cbc_test(void) {
    void *in_buf = memalign(64, 128);
    void *out_buf = memalign(64, 128);
    void *iv_buf = memalign(64, 8);
    void *key_buf = memalign(64, 24);

    memcpy(in_buf, des3_ede_cbc_test_buf_plain, 128);
    memcpy(iv_buf, des3_ede_cbc_test_iv, 8);
    memcpy(key_buf, des3_ede_cbc_test_key, 24);
    memset(out_buf, 0xff, 128);

    caam_tdes_cbc(1, iv_buf, 8, key_buf, 24, in_buf, 128, out_buf, 128);
    if (memcmp(out_buf, des3_ede_cbc_test_buf_cipher, 128))
        TLOGE("DES EDE CBC encrytion test failed!\n");
    else
        TLOGE("DES EDE CBC  encrytion test passed!\n");

    memset(out_buf, 0xff, 128);
    memcpy(in_buf, des3_ede_cbc_test_buf_cipher, 128);
    caam_tdes_cbc(0, iv_buf, 8, key_buf, 24, in_buf, 128, out_buf, 128);
    if (memcmp(out_buf, des3_ede_cbc_test_buf_plain, 128))
        TLOGE("DES EDE CBC decrytion test failed!\n");
    else
        TLOGE("DES EDE CBC decrytion test passed!\n");

    free(in_buf);
    free(out_buf);
    free(iv_buf);
    free(key_buf);
}

void caam_test(void) {
    caam_hwrng_test();
    caam_blob_test();
    caam_kdfv1_root_key_test();
    caam_aes_test();
    caam_hash_test();
    caam_aes_cbc_test();
    caam_aes_ecb_test();
    caam_aes_ctr_test();
    caam_aes_gcm_test();
    caam_tdes_ecb_test();
    caam_tdes_cbc_test();
}

#endif /* WITH_CAAM_SELF_TEST */
