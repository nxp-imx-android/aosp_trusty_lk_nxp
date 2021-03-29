#include <stdio.h>
#include <string.h>
#include <lk/init.h>
#include <kernel/mutex.h>
#include <arch/ops.h>
#include <imx-regs.h>
#include <kernel/vm.h>
#include <kernel/mutex.h>
#include <reg.h>

/* Configuration and special key registers */
#define CAAM_JR1MIDR (0x0018 + CAAM_BASE_ADDR)
#define CAAM_JR1LIDR (0x001c + CAAM_BASE_ADDR)

/* RNG registers */
#define CAAM_RTMCTL (0x0600 + CAAM_BASE_ADDR)
#define CAAM_RTSDCTL (0x0610 + CAAM_BASE_ADDR)
#define CAAM_RTFRQMIN (0x0618 + CAAM_BASE_ADDR)
#define CAAM_RTFRQMAX (0x061C + CAAM_BASE_ADDR)
#define CAAM_RDSTA (0x06C0 + CAAM_BASE_ADDR)

/* imx8m Job Ring 1 registers */
#define CAAM_IRBAR1 (0x2004 + CAAM_BASE_ADDR)
#define CAAM_IRSR1 (0x200c + CAAM_BASE_ADDR)
#define CAAM_IRJAR1 (0x201c + CAAM_BASE_ADDR)
#define CAAM_ORBAR1 (0x2024 + CAAM_BASE_ADDR)
#define CAAM_ORSR1 (0x202c + CAAM_BASE_ADDR)
#define CAAM_ORJRR1 (0x2034 + CAAM_BASE_ADDR)
#define CAAM_ORSFR1 (0x203c + CAAM_BASE_ADDR)
#define CAAM_JRCFGR1_MS (0x2050 + CAAM_BASE_ADDR)
#define CAAM_JRCFGR1_LS (0x2054 + CAAM_BASE_ADDR)

#ifdef MACH_IMX8Q
/* imx8q Job Ring 2 registers */
#define CAAM_IRBAR2 (0x30004 + CAAM_BASE_ADDR)
#define CAAM_IRSR2 (0x3000c + CAAM_BASE_ADDR)
#define CAAM_IRJAR2 (0x3001c + CAAM_BASE_ADDR)
#define CAAM_ORBAR2 (0x30024 + CAAM_BASE_ADDR)
#define CAAM_ORSR2 (0x3002c + CAAM_BASE_ADDR)
#define CAAM_ORSFR2 (0x3003c + CAAM_BASE_ADDR)
#define CAAM_ORJRR2 (0x30034 + CAAM_BASE_ADDR)
#endif

#define RNG_INST_DESC1 0xB0800009
#define RNG_INST_DESC2 0x12A00008
#define RNG_INST_DESC3 0x01020304
#define RNG_INST_DESC4 0x05060708
#define RNG_INST_DESC5 0x82500404
#define RNG_INST_DESC6 0xA2000001
#define RNG_INST_DESC7 0x10880004
#define RNG_INST_DESC8 0x00000001
#define RNG_INST_DESC9 0x82501000

#define JRCFG_LS_IMSK 0x00000001
#define JOB_RING_STS (0xF << 28)
#define RDSTA_IF0 1
#define RDSTA_SKVN (1 << 30)
#define RTMCTL_PGM (1 << 16)
#define RTMCTL_ERR (1 << 12)
#define RNG_TRIM_OSC_DIV 0
#define RNG_TRIM_ENT_DLY 3200


struct caam_job_rings {
    uint32_t in[1];  /* single entry input ring */
    uint32_t out[2]; /* single entry output ring (consists of two words) */
};

/*
 * According to CAAM docs max number of descriptors in single sequence is 64
 * You can chain them though.
 */
#define MAX_DSC_NUM 64

struct caam_job {
    uint32_t dsc[MAX_DSC_NUM]; /* job descriptors */
    uint32_t dsc_used;         /* number of filled entries */
    uint32_t status;           /* job result */
};

static struct caam_job_rings* g_rings;
static struct caam_job* g_job;

const uint32_t rng_inst_dsc[] = {
        RNG_INST_DESC1, RNG_INST_DESC2, RNG_INST_DESC3,
        RNG_INST_DESC4, RNG_INST_DESC5, RNG_INST_DESC6,
        RNG_INST_DESC7, RNG_INST_DESC8, RNG_INST_DESC9};

static void setup_job_rings(void) {
    paddr_t g_rings_pa;

    /* Initialize job ring addresses */
    memset(g_rings, 0, sizeof(*g_rings));
    g_rings_pa = vaddr_to_paddr((void *)g_rings);

#ifdef MACH_IMX8Q
    /* imx8q Job Ring 0 and 1 are owned and reserved by SECO, use Job Ring 2 here. */
    writel((uint32_t)g_rings_pa + offsetof(struct caam_job_rings, in),
           CAAM_IRBAR2);  // input ring address
    writel((uint32_t)g_rings_pa + offsetof(struct caam_job_rings, out),
           CAAM_ORBAR2);  // output ring address

    /* Initialize job ring sizes */
    writel(countof(g_rings->in), CAAM_IRSR2);
    writel(countof(g_rings->in), CAAM_ORSR2);
#else
    writel((uint32_t)g_rings_pa + offsetof(struct caam_job_rings, in),
           CAAM_IRBAR1);  // input ring address
    writel((uint32_t)g_rings_pa + offsetof(struct caam_job_rings, out),
           CAAM_ORBAR1);  // output ring address

    /* Initialize job ring sizes */
    writel(countof(g_rings->in), CAAM_IRSR1);
    writel(countof(g_rings->in), CAAM_ORSR1);
#endif
}

static void run_job(struct caam_job* job) {
    uint32_t job_pa;

    /* prepare dma job */
    job_pa = vaddr_to_paddr(job->dsc);
    arch_clean_cache_range((addr_t)(job->dsc), job->dsc_used * sizeof(uint32_t));

    /* Add job to input ring */
    g_rings->out[0] = 0;
    g_rings->out[1] = 0;
    g_rings->in[0] = job_pa;
    arch_clean_cache_range((addr_t)g_rings, sizeof(*g_rings));

    /* start job */
    /* imx8q Job Ring 0 and 1 are owned and reserved by SECO, use Job Ring 2 here. */
#ifdef MACH_IMX8Q
    writel(1, CAAM_IRJAR2);
#else
    writel(1, CAAM_IRJAR1);
#endif

    /* Wait for job ring to complete the job: 1 completed job expected */
#ifdef MACH_IMX8Q
    while (readl(CAAM_ORSFR2) != 1)
#else
    while (readl(CAAM_ORSFR1) != 1)
#endif
        ;

    arch_clean_invalidate_cache_range((addr_t)g_rings->out, sizeof(g_rings->out));

    /* check that descriptor address is the one expected in the out ring */
    assert(g_rings->out[0] == job_pa);

    job->status = g_rings->out[1];

    /* remove job */
#ifdef MACH_IMX8Q
    writel(1, CAAM_ORJRR2);
#else
    writel(1, CAAM_ORJRR1);
#endif
}

void imx_caam_open(void) {
    uint32_t temp_reg;

    /* HAB disables interrupts for JR0 so do the same here */
    temp_reg = readl(CAAM_JRCFGR1_LS) | JRCFG_LS_IMSK;
    writel(temp_reg, CAAM_JRCFGR1_LS);

    /* if RNG already instantiated then skip it */
    if ((readl(CAAM_RDSTA) & RDSTA_IF0) != RDSTA_IF0) {
        printf("CAAM RNG should already be instantiated in SPL!\n");
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
                printf("job failed (0x%08x)\n", g_job->status);
                temp_reg = readl(CAAM_RTMCTL) | RTMCTL_ERR;
                writel(temp_reg, CAAM_RTMCTL);
            } else {
                break;
            }
        }

        /* ensure that the RNG was correctly instantiated */
        temp_reg = readl(CAAM_RDSTA);
        if (temp_reg != (RDSTA_IF0 | RDSTA_SKVN)) {
            panic("Bad RNG state 0x%X\n", temp_reg);
        }
    }

    return;
}

void init_caam_env(uint level) {

    /* allocate rings */
    g_rings = memalign(16, sizeof(struct caam_job_rings));
    if (!g_rings) {
        panic("out of memory allocating rings\n");
    }

    /* allocate jobs */
    g_job = memalign(MAX_DSC_NUM * sizeof(uint32_t), sizeof(struct caam_job));
    if (!g_job) {
        panic("out of memory allocating job\n");
    }

#if defined(MACH_IMX8MQ) || defined(MACH_IMX8MM) || defined(MACH_IMX8MP)
    /* The JR0 is assigned to non-secure world by default in ATF, assign
     * it to secure world here. */
    uint32_t cfg_ms = 0;
    uint32_t cfg_ls = 0;

    cfg_ms = 0x1 << 0;  /* JRxDID_MS_PRIM_DID */
    cfg_ms |= (0x1 << 4) | (0x1 << 15); /* JRxDID_MS_PRIM_TZ | JRxDID_MS_TZ_OWN */
    cfg_ms |= (0x1 << 16); /* JRxDID_MS_AMTD */
    cfg_ms |= (0x1 << 19); /* JRxDID_MS_PRIM_ICID */
    cfg_ms |= (0x1 << 31); /* JRxDID_MS_LDID */
    cfg_ms |= (0x1 << 17); /* JRxDID_MS_LAMTD */

    writel(cfg_ms, CAAM_JR1MIDR);
    writel(cfg_ls, CAAM_JR1LIDR);
#endif

    /* Initialize job ring addresses */
    setup_job_rings();
#ifndef MACH_IMX8Q
    imx_caam_open();
#endif
}

static uint8_t entropy[32] __attribute__((aligned(64))) = {
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18,
        0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10
};

void imx_trusty_rand_add_entropy(const void *buf, size_t len) {
    if (len == 0)
        return;

    uint32_t enp = 0;
    for (size_t i = 0; i < len; i++) {
        enp ^= ((enp << 8) | (enp >> 24)) ^ ((const uint8_t *)buf)[i];
    }

    ((uint32_t *)entropy)[0] = enp;
}

static struct mutex lock = MUTEX_INITIAL_VALUE(lock);

int imx_rand(void) {
    int rand, *rand_buf;
    paddr_t ptr, entropy_pa;

    mutex_acquire(&lock);

    rand_buf = memalign(64, sizeof(int));
    ptr = vaddr_to_paddr(rand_buf);
    entropy_pa = vaddr_to_paddr(entropy);
    arch_clean_cache_range((addr_t)(rand_buf), sizeof(int));
    arch_clean_cache_range((addr_t)(entropy), sizeof(entropy));

    g_job->dsc[0] = 0xB0800006;
    g_job->dsc[1] = 0x12200020;
    g_job->dsc[2] = (uint32_t)entropy_pa;
    g_job->dsc[3] = 0x82500800;
    g_job->dsc[4] = 0x60340000 | (0x0000ffff & sizeof(int));
    g_job->dsc[5] = (uint32_t)ptr;
    g_job->dsc_used = 6;

    run_job(g_job);

    if (g_job->status & JOB_RING_STS) {
        printf("job failed (0x%08x), will return fixed value!\n", g_job->status);
        free(rand_buf);
        return (int)((unsigned int)12345 * 1664525 + 1013904223);
    }
    arch_clean_invalidate_cache_range((addr_t)(rand_buf), sizeof(int));

    mutex_release(&lock);

    rand = *rand_buf;
    free(rand_buf);
    return rand;
}

LK_INIT_HOOK(imx_caam, init_caam_env, LK_INIT_LEVEL_KERNEL - 1);
