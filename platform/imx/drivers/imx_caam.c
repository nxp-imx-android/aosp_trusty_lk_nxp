#include <stdio.h>
#include <string.h>
#include <lk/init.h>
#include <kernel/mutex.h>
#include <arch/ops.h>
#include <imx-regs.h>
#include <kernel/vm.h>
#include <kernel/mutex.h>
#include <reg.h>
#include "imx_caam.h"

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

static void setup_job_rings(void) {
    paddr_t g_rings_pa;

    /* Initialize job ring addresses */
    memset(g_rings, 0, sizeof(*g_rings));
    g_rings_pa = vaddr_to_paddr((void *)g_rings);

    writel((uint32_t)g_rings_pa + offsetof(struct caam_job_rings, in),
           CAAM_IRBAR);  // input ring address
    writel((uint32_t)g_rings_pa + offsetof(struct caam_job_rings, out),
           CAAM_ORBAR);  // output ring address

    /* Initialize job ring sizes */
    writel(countof(g_rings->in), CAAM_IRSR);
    writel(countof(g_rings->in), CAAM_ORSR);
}

#ifdef MACH_IMX8ULP
uint32_t caam_jr0did_ms = 0;
uint32_t caam_jr0did_ls = 0;
uint32_t caam_jr1did_ms = 0;
uint32_t caam_jr1did_ls = 0;
uint32_t caam_jr2did_ms = 0;
uint32_t caam_jr2did_ls = 0;
uint32_t caam_jr3did_ms = 0;
uint32_t caam_jr3did_ls = 0;

uint32_t caam_irbar_jr0 = 0;
uint32_t caam_irbar_jr1 = 0;
uint32_t caam_irbar_jr2 = 0;
uint32_t caam_irbar_jr3 = 0;
uint32_t caam_orbar_jr0 = 0;
uint32_t caam_orbar_jr1 = 0;
uint32_t caam_orbar_jr2 = 0;
uint32_t caam_orbar_jr3 = 0;
uint32_t caam_irsr_jr0 = 0;
uint32_t caam_irsr_jr1 = 0;
uint32_t caam_irsr_jr2 = 0;
uint32_t caam_irsr_jr3 = 0;
uint32_t caam_orsr_jr0 = 0;
uint32_t caam_orsr_jr1 = 0;
uint32_t caam_orsr_jr2 = 0;
uint32_t caam_orsr_jr3 = 0;

void save_caam_regs(void)
{
    caam_jr0did_ms = readl(CAAM_JR0DID_MS);
    caam_jr0did_ls = readl(CAAM_JR0DID_LS);
    caam_jr1did_ms = readl(CAAM_JR1DID_MS);
    caam_jr1did_ls = readl(CAAM_JR1DID_MS);
    caam_jr2did_ms = readl(CAAM_JR2DID_MS);
    caam_jr2did_ls = readl(CAAM_JR2DID_MS);
    caam_jr3did_ms = readl(CAAM_JR3DID_MS);
    caam_jr3did_ls = readl(CAAM_JR3DID_MS);

    caam_irbar_jr0 = readl(CAAM_IRBAR_JR0);
    caam_irbar_jr1 = readl(CAAM_IRBAR_JR1);
    caam_irbar_jr2 = readl(CAAM_IRBAR_JR2);
    caam_irbar_jr3 = readl(CAAM_IRBAR_JR3);

    caam_orbar_jr0 = readl(CAAM_ORBAR_JR0);
    caam_orbar_jr1 = readl(CAAM_ORBAR_JR1);
    caam_orbar_jr2 = readl(CAAM_ORBAR_JR2);
    caam_orbar_jr3 = readl(CAAM_ORBAR_JR3);

    caam_irsr_jr0 = readl(CAAM_IRSR_JR0);
    caam_irsr_jr1 = readl(CAAM_IRSR_JR1);
    caam_irsr_jr2 = readl(CAAM_IRSR_JR2);
    caam_irsr_jr3 = readl(CAAM_IRSR_JR3);

    caam_orsr_jr0 = readl(CAAM_ORSR_JR0);
    caam_orsr_jr1 = readl(CAAM_ORSR_JR1);
    caam_orsr_jr2 = readl(CAAM_ORSR_JR2);
    caam_orsr_jr3 = readl(CAAM_ORSR_JR3);
}

void restore_caam_regs(void)
{
    writel(caam_jr0did_ms, CAAM_JR0DID_MS);
    writel(caam_jr0did_ls, CAAM_JR0DID_LS);
    writel(caam_jr1did_ms, CAAM_JR1DID_MS);
    writel(caam_jr1did_ls, CAAM_JR1DID_LS);
    writel(caam_jr2did_ms, CAAM_JR2DID_MS);
    writel(caam_jr2did_ls, CAAM_JR2DID_LS);
    writel(caam_jr3did_ms, CAAM_JR3DID_MS);
    writel(caam_jr3did_ls, CAAM_JR3DID_LS);

    writel(caam_irbar_jr0, CAAM_IRBAR_JR0);
    writel(caam_irbar_jr1, CAAM_IRBAR_JR1);
    writel(caam_irbar_jr2, CAAM_IRBAR_JR2);
    writel(caam_irbar_jr3, CAAM_IRBAR_JR3);

    writel(caam_orbar_jr0, CAAM_ORBAR_JR0);
    writel(caam_orbar_jr1, CAAM_ORBAR_JR1);
    writel(caam_orbar_jr2, CAAM_ORBAR_JR2);
    writel(caam_orbar_jr3, CAAM_ORBAR_JR3);

    writel(caam_irsr_jr0, CAAM_IRSR_JR0);
    writel(caam_irsr_jr1, CAAM_IRSR_JR1);
    writel(caam_irsr_jr2, CAAM_IRSR_JR2);
    writel(caam_irsr_jr3, CAAM_IRSR_JR3);

    writel(caam_orsr_jr0, CAAM_ORSR_JR0);
    writel(caam_orsr_jr1, CAAM_ORSR_JR1);
    writel(caam_orsr_jr2, CAAM_ORSR_JR2);
    writel(caam_orsr_jr3, CAAM_ORSR_JR3);
}
#endif

#ifndef MACH_IMX8Q
void caam_set_did(void) {
    /* The JR0 is assigned to non-secure world by default in ATF, assign
     * it to secure world here. */
    uint32_t cfg_ms = 0;
    uint32_t cfg_ls = 0;

#ifdef MACH_IMX8ULP
    cfg_ms = 0x7 << 0;  /* JRxDID_MS_PRIM_DID */
#else
    cfg_ms = 0x1 << 0;  /* JRxDID_MS_PRIM_DID */
#endif

    cfg_ms |= (0x1 << 4) | (0x1 << 15); /* JRxDID_MS_PRIM_TZ | JRxDID_MS_TZ_OWN */
    cfg_ms |= (0x1 << 16); /* JRxDID_MS_AMTD */
    cfg_ms |= (0x1 << 19); /* JRxDID_MS_PRIM_ICID */
    cfg_ms |= (0x1 << 31); /* JRxDID_MS_LDID */
    cfg_ms |= (0x1 << 17); /* JRxDID_MS_LAMTD */

    writel(cfg_ms, CAAM_JRMIDR);
    writel(cfg_ls, CAAM_JRLIDR);
}

static int jr_reset(void)
{
    /*
     * Function reset the Job Ring HW
     * Reset is done in 2 steps:
     *  - Flush all pending jobs (Set RESET bit)
     *  - Reset the Job Ring (Set RESET bit second time)
     */
    u16 timeout = 10000;
    u32 reg_val;

    /* Mask interrupts to poll for reset completion status */
    reg_val = readl(CAAM_JRCFGR_LS) | BM_JRCFGR_LS_IMSK;
    writel(reg_val, CAAM_JRCFGR_LS);

    /* Initiate flush (required prior to reset) */
    writel(JRCR_RESET, CAAM_JRCR);
    do {
        reg_val = readl(CAAM_JRINTR);
        reg_val &= BM_JRINTR_HALT;
    } while ((reg_val == JRINTR_HALT_ONGOING) && --timeout);

    if (!timeout  || reg_val != JRINTR_HALT_DONE) {
        printf("Failed to flush job ring\n");
        return -1;
    }

    /* Initiate reset */
    timeout = 100;
    writel(JRCR_RESET, CAAM_JRCR);
    do {
        reg_val = readl(CAAM_JRCR);
    } while ((reg_val & JRCR_RESET) && --timeout);

    if (!timeout) {
        printf("Failed to reset job ring\n");
        return -1;
    }

    return 0;
}
#endif

static void run_job(struct caam_job* job) {
    uint32_t job_pa;
    uint32_t timeout = 10000000;

    /* prepare dma job */
    job_pa = vaddr_to_paddr(job->dsc);
    arch_clean_cache_range((addr_t)(job->dsc), job->dsc_used * sizeof(uint32_t));

    /* Add job to input ring */
    g_rings->out[0] = 0;
    g_rings->out[1] = 0;
    g_rings->in[0] = job_pa;
    arch_clean_cache_range((addr_t)g_rings, sizeof(*g_rings));

    /* start job */
    writel(1, CAAM_IRJAR);

    /* Wait for job ring to complete the job: 1 completed job expected */
    while ((readl(CAAM_ORSFR) != 1) && (--timeout))
        ;

    if (!timeout)
        panic("CAAM run_job timeout!\n");

    arch_clean_invalidate_cache_range((addr_t)g_rings->out, sizeof(g_rings->out));

    /* check that descriptor address is the one expected in the out ring */
    assert(g_rings->out[0] == job_pa);

    job->status = g_rings->out[1];

    /* remove job */
    writel(1, CAAM_ORJRR);
}

#ifndef MACH_IMX8Q
static void kick_trng(u32 ent_delay)
{
    u32 samples  = 512; /* number of bits to generate and test */
    u32 mono_min = 195;
    u32 mono_max = 317;
    u32 mono_range  = mono_max - mono_min;
    u32 poker_min = 1031;
    u32 poker_max = 1600;
    u32 poker_range = poker_max - poker_min + 1;
    u32 retries    = 2;
    u32 lrun_max   = 32;
    s32 run_1_min   = 27;
    s32 run_1_max   = 107;
    s32 run_1_range = run_1_max - run_1_min;
    s32 run_2_min   = 7;
    s32 run_2_max   = 62;
    s32 run_2_range = run_2_max - run_2_min;
    s32 run_3_min   = 0;
    s32 run_3_max   = 39;
    s32 run_3_range = run_3_max - run_3_min;
    s32 run_4_min   = -1;
    s32 run_4_max   = 26;
    s32 run_4_range = run_4_max - run_4_min;
    s32 run_5_min   = -1;
    s32 run_5_max   = 18;
    s32 run_5_range = run_5_max - run_5_min;
    s32 run_6_min   = -1;
    s32 run_6_max   = 17;
    s32 run_6_range = run_6_max - run_6_min;
    u32 val;

    /* Put RNG in program mode */
    /* Setting both RTMCTL:PRGM and RTMCTL:TRNG_ACC causes TRNG to
     * properly invalidate the entropy in the entropy register and
     * force re-generation.
     */
    val = readl(CAAM_RTMCTL) | RTMCTL_PGM | RTMCTL_ACC;
    writel(val, CAAM_RTMCTL);

    /* Configure the RNG Entropy Delay
     * Performance-wise, it does not make sense to
     * set the delay to a value that is lower
     * than the last one that worked (i.e. the state handles
     * were instantiated properly. Thus, instead of wasting
     * time trying to set the values controlling the sample
     * frequency, the function simply returns.
     */
    val = readl(CAAM_RTSDCTL);
    val &= BM_TRNG_ENT_DLY;
    val >>= BS_TRNG_ENT_DLY;
    if (ent_delay < val) {
        /* Put RNG4 into run mode */
        val = readl(CAAM_RTMCTL);
        val &= ~(RTMCTL_PGM | RTMCTL_ACC);
        writel(val, CAAM_RTMCTL);
        return;
    }

    val = (ent_delay << BS_TRNG_ENT_DLY) | samples;
    writel(val, CAAM_RTSDCTL);

    /*
     * Recommended margins (min,max) for freq. count:
     *   freq_mul = RO_freq / TRNG_clk_freq
     *   rtfrqmin = (ent_delay x freq_mul) >> 1;
     *   rtfrqmax = (ent_delay x freq_mul) << 3;
     * Given current deployments of CAAM in i.MX SoCs, and to simplify
     * the configuration, we consider [1,16] to be a safe interval
     * for the freq_mul and the limits of the interval are used to compute
     * rtfrqmin, rtfrqmax
     */
    writel(ent_delay >> 1, CAAM_RTFRQMIN);
    writel(ent_delay << 7, CAAM_RTFRQMAX);

    writel((retries << 16) | lrun_max, CAAM_RTSCMISC);
    writel(poker_max, CAAM_RTPKRMAX);
    writel(poker_range, CAAM_RTPKRRNG);
    writel((mono_range << 16) | mono_max, CAAM_RTSCML);
    writel((run_1_range << 16) | run_1_max, CAAM_RTSCR1L);
    writel((run_2_range << 16) | run_2_max, CAAM_RTSCR2L);
    writel((run_3_range << 16) | run_3_max, CAAM_RTSCR3L);
    writel((run_4_range << 16) | run_4_max, CAAM_RTSCR4L);
    writel((run_5_range << 16) | run_5_max, CAAM_RTSCR5L);
    writel((run_6_range << 16) | run_6_max, CAAM_RTSCR6PL);

    val = readl(CAAM_RTMCTL);
    /*
     * Select raw sampling in both entropy shifter
     * and statistical checker
     */
    val &= ~BM_TRNG_SAMP_MODE;
    val |= TRNG_SAMP_MODE_RAW_ES_SC;
    /* Put RNG4 into run mode */
    val &= ~(RTMCTL_PGM | RTMCTL_ACC);
    /*test with sample mode only */
    writel(val, CAAM_RTMCTL);

    /* Clear the ERR bit in RTMCTL if set. The TRNG error can occur when the
     * RNG clock is not within 1/2x to 8x the system clock.
     * This error is possible if ROM code does not initialize the system PLLs
     * immediately after PoR.
     */
    /* setbits_le32(CAAM_RTMCTL, RTMCTL_ERR); */
}

static void do_clear_rng_error(void)
{
    u32 val;

    val = readl(CAAM_RTMCTL);

    if (val & (RTMCTL_ERR | RTMCTL_FCT_FAIL)) {
        val = readl(CAAM_RTMCTL) | RTMCTL_ERR;
        writel(val, CAAM_RTMCTL);
        val = readl(CAAM_RTMCTL);
    }
}

/*
 *  Descriptors to instantiate SH0, SH1, load the keys
 */
static const u32 rng_inst_sh0_desc[] = {
    /* Header, don't setup the size */
    CAAM_HDR_CTYPE | CAAM_HDR_ONE | CAAM_HDR_START_INDEX(0),
    /* Operation instantiation (sh0) */
    CAAM_PROTOP_CTYPE | CAAM_C1_RNG | ALGO_RNG_SH(0) | ALGO_RNG_PR |
    ALGO_RNG_INSTANTIATE,
};

static const u32 rng_inst_sh1_desc[] = {
    /* wait for done - Jump to next entry */
    CAAM_C1_JUMP | CAAM_JUMP_LOCAL | CAAM_JUMP_TST_ALL_COND_TRUE | CAAM_JUMP_OFFSET(1),
    /* Clear written register (write 1) */
    CAAM_C0_LOAD_IMM | CAAM_DST_CLEAR_WRITTEN | sizeof(u32),
    0x00000001,
    /* Operation instantiation (sh1) */
    CAAM_PROTOP_CTYPE | CAAM_C1_RNG | ALGO_RNG_SH(1) | ALGO_RNG_PR | ALGO_RNG_INSTANTIATE,
};

static const u32 rng_inst_load_keys[] = {
    /* wait for done - Jump to next entry */
    CAAM_C1_JUMP | CAAM_JUMP_LOCAL | CAAM_JUMP_TST_ALL_COND_TRUE | CAAM_JUMP_OFFSET(1),
    /* Clear written register (write 1) */
    CAAM_C0_LOAD_IMM | CAAM_DST_CLEAR_WRITTEN | sizeof(u32),
    0x00000001,
    /* Generate the Key */
    CAAM_PROTOP_CTYPE | CAAM_C1_RNG | BM_ALGO_RNG_SK | ALGO_RNG_GENERATE,
};

static void do_inst_desc(u32 *desc, u32 status)
{
    u32 *pdesc = desc;
    u8  desc_len;
    bool add_sh0   = false;
    bool add_sh1   = false;
    bool load_keys = false;

    /*
     * Modify the the descriptor to remove if necessary:
     *  - The key loading
     *  - One of the SH already instantiated
     */
    desc_len = RNG_DESC_SH0_SIZE;
    if ((status & RDSTA_IF0) != RDSTA_IF0)
        add_sh0 = true;

    if ((status & RDSTA_IF1) != RDSTA_IF1) {
        add_sh1 = true;
        if (add_sh0)
            desc_len += RNG_DESC_SH1_SIZE;
    }

    if ((status & RDSTA_SKVN) != RDSTA_SKVN) {
        load_keys = true;
        desc_len += RNG_DESC_KEYS_SIZE;
    }

    /* Copy the SH0 descriptor anyway */
    memcpy(pdesc, rng_inst_sh0_desc, sizeof(rng_inst_sh0_desc));
    pdesc += RNG_DESC_SH0_SIZE;

    if (load_keys) {
        printf("RNG - Load keys\n");
        memcpy(pdesc, rng_inst_load_keys, sizeof(rng_inst_load_keys));
        pdesc += RNG_DESC_KEYS_SIZE;
    }

    if (add_sh1) {
        if (add_sh0) {
            printf("RNG - Instantiation of SH0 and SH1\n");
            /* Add the sh1 descriptor */
            memcpy(pdesc, rng_inst_sh1_desc, sizeof(rng_inst_sh1_desc));
        } else {
            printf("RNG - Instantiation of SH1 only\n");
            /* Modify the SH0 descriptor to instantiate only SH1 */
            desc[1] &= ~BM_ALGO_RNG_SH;
            desc[1] |= ALGO_RNG_SH(1);
        }
    }

    /* Setup the descriptor size */
    desc[0] &= ~(0x3F);
    desc[0] |= CAAM_HDR_DESCLEN(desc_len);
    g_job->dsc_used = desc_len;
}

static int do_instantiation(void)
{
    int ret = -1;
    u32 ent_delay;
    u32 status;

    ent_delay = TRNG_SDCTL_ENT_DLY_MIN;

    do {
        /* Read the CAAM RNG status */
        status = readl(CAAM_RDSTA);

        if ((status & RDSTA_IF0) != RDSTA_IF0) {
            /* Configure the RNG entropy delay */
            kick_trng(ent_delay);
            ent_delay += 400;
        }

        do_clear_rng_error();

        if ((status & (RDSTA_IF0 | RDSTA_IF1)) != (RDSTA_IF0 | RDSTA_IF1)) {
            /* Prepare the instantiation descriptor */
            do_inst_desc(g_job->dsc, status);

            /* Run Job */
            run_job(g_job);
        } else {
            ret = 0;
            printf("RNG instantiation done (%d)\n", ent_delay);
            goto end_instantation;
        }
    } while (ent_delay < TRNG_SDCTL_ENT_DLY_MAX);

    printf("RNG Instantation Failure - Entropy delay (%d)\n", ent_delay);
    ret = -1;

end_instantation:
    return ret;
}

static void rng_init(void)
{
    int  ret;

    ret = jr_reset();
    if (ret != 0) {
        printf("Error CAAM JR reset\n");
        return;
    }

    ret = do_instantiation();

    if (ret != 0)
        printf("Error do_instantiation\n");

    jr_reset();

    return;
}

static void do_cfg_jrqueue(void)
{
    u32 value = 0;

    /* Configure the HW Job Rings */
    setup_job_rings();

    value = readl(CAAM_JRINTR) | JRINTR_JRI;
    writel(value, CAAM_JRINTR);

    /*
     * Configure interrupts but disable it:
     * Optimization to generate an interrupt either when there are
     * half of the job done or when there is a job done and
     * 10 clock cycles elapse without new job complete
     */
    value = 10 << BS_JRCFGR_LS_ICTT;
    value |= (1 << BS_JRCFGR_LS_ICDCT) & BM_JRCFGR_LS_ICDCT;
    value |= BM_JRCFGR_LS_ICEN;
    value |= BM_JRCFGR_LS_IMSK;
    writel(value, CAAM_JRCFGR_LS);

    /* Enable deco watchdog */
    value = readl(CAAM_MCFGR) | BM_MCFGR_WDE;
    writel(value, CAAM_MCFGR);
}

/*!
 * Initialize the CAAM.
 *
 */
void caam_open(void)
{
    u32 temp_reg;
    u32 init_mask;

    /* reset the CAAM */
    temp_reg = readl(CAAM_MCFGR) | CAAM_MCFGR_DMARST | CAAM_MCFGR_SWRST;
    writel(temp_reg,  CAAM_MCFGR);
    while (readl(CAAM_MCFGR) & CAAM_MCFGR_DMARST)
          ;

#ifdef MACH_IMX8ULP
    restore_caam_regs();
#endif

    jr_reset();
    do_cfg_jrqueue();

    /* Check if the RNG is already instantiated */
    temp_reg = readl(CAAM_RDSTA);
    init_mask = RDSTA_IF0 | RDSTA_IF1 | RDSTA_SKVN;
    if ((temp_reg & init_mask) == init_mask) {
        printf("RNG already instantiated 0x%X\n", temp_reg);
        return;
    }

    rng_init();
}
#endif

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

#ifndef MACH_IMX8Q
    caam_set_did();
#endif

    /* Initialize job ring addresses */
    setup_job_rings();
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

void platform_random_get_bytes(uint8_t *buf, size_t len) {
    while (len) {
        uint32_t val = (uint32_t)imx_rand();
        size_t todo = len;
        for (size_t i = 0; i < sizeof(val) && i < todo; i++, len--) {
            *buf++ = val & 0xff;
            val >>= 8;
        }
   }
};

#ifdef MACH_IMX8ULP
static bool caam_resume_flag = true;
static bool caam_suspend_flag = true;

static void imx_caam_resume_cpu(uint level)
{
    mutex_acquire(&lock);
    if (caam_resume_flag) {
        caam_open();
        caam_resume_flag = false;
        caam_suspend_flag = true;
    }
    mutex_release(&lock);
}

static void imx_caam_suspend_cpu(uint level)
{
    mutex_acquire(&lock);
    if (caam_suspend_flag) {
        save_caam_regs();
        caam_suspend_flag = false;
        caam_resume_flag = true;
    }
    mutex_release(&lock);
}

/*
 * CAAM on imx8ulp will lose power during suspend/resume,
 * init CAAM and do RNG instantiation during resume.
 */
LK_INIT_HOOK_FLAGS(imx_caam_resume_cpu, imx_caam_resume_cpu, LK_INIT_LEVEL_KERNEL - 1, LK_INIT_FLAG_CPU_RESUME);

LK_INIT_HOOK_FLAGS(imx_caam_suspend_cpu, imx_caam_suspend_cpu, LK_INIT_LEVEL_KERNEL - 1, LK_INIT_FLAG_CPU_SUSPEND);
#endif

LK_INIT_HOOK(imx_caam, init_caam_env, LK_INIT_LEVEL_KERNEL - 1);
