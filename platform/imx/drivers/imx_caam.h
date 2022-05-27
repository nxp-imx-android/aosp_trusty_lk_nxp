#ifndef __IMX_CAAM_H__
#define __IMX_CAAM_H__

#define BIT(nr) (1UL << (nr))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define CAAM_MCFGR_DMARST   BIT(28)      /* CAAM DMA reset */
#define CAAM_MCFGR_SWRST    BIT(31)      /* CAAM SW reset */
#define JRCR_RESET       (1)
#define JRINTR_JRI          (0x1)
#define BS_TRNG_ENT_DLY     (16)
#define BM_TRNG_ENT_DLY     (0xffffUL << BS_TRNG_ENT_DLY)
#define BM_TRNG_SAMP_MODE   (3)
#define TRNG_SAMP_MODE_RAW_ES_SC (1)
#define BS_JRINTR_HALT      (2)
#define BS_JRCFGR_LS_ICTT   (16)
#define BS_JRCFGR_LS_ICDCT  (8)
#define BM_JRCFGR_LS_ICDCT  (0xFFUL << BS_JRCFGR_LS_ICDCT)
#define BS_JRCFGR_LS_ICEN   (1)
#define BM_JRCFGR_LS_ICEN   (0x1UL << BS_JRCFGR_LS_ICEN)
#define BS_JRCFGR_LS_IMSK   (0)
#define BM_JRCFGR_LS_IMSK   (0x1UL << BS_JRCFGR_LS_IMSK)
#define BS_MCFGR_WDE        (30)
#define BM_MCFGR_WDE        (0x1 << BS_MCFGR_WDE)
#define JRINTR_HALT_ONGOING (0x1 << BS_JRINTR_HALT)
#define JRINTR_HALT_DONE    (0x2 << BS_JRINTR_HALT)
#define BM_JRINTR_HALT      (0x3 << BS_JRINTR_HALT)
#define TRNG_SDCTL_ENT_DLY_MIN (3200)
#define TRNG_SDCTL_ENT_DLY_MAX (4800)

#define CAAM_MCFGR (0x0004 + CAAM_BASE_ADDR)

/* RNG registers */
#define CAAM_RTMCTL (0x0600 + CAAM_BASE_ADDR)
#define CAAM_RTSCMISC (0x0604 + CAAM_BASE_ADDR)
#define CAAM_RTPKRRNG (0x0608 + CAAM_BASE_ADDR)
#define CAAM_RTPKRMAX (0x060c + CAAM_BASE_ADDR)
#define CAAM_RTSDCTL (0x0610 + CAAM_BASE_ADDR)
#define CAAM_RTFRQMIN (0x0618 + CAAM_BASE_ADDR)
#define CAAM_RTFRQMAX (0x061C + CAAM_BASE_ADDR)
#define CAAM_RTSCML (0x0620 + CAAM_BASE_ADDR)
#define CAAM_RTSCR1L (0x0624 + CAAM_BASE_ADDR)
#define CAAM_RTSCR2L (0x0628 + CAAM_BASE_ADDR)
#define CAAM_RTSCR3L (0x062C + CAAM_BASE_ADDR)
#define CAAM_RTSCR4L (0x0630 + CAAM_BASE_ADDR)
#define CAAM_RTSCR5L (0x0634 + CAAM_BASE_ADDR)
#define CAAM_RTSCR6PL (0x0638 + CAAM_BASE_ADDR)
#define CAAM_RDSTA (0x06C0 + CAAM_BASE_ADDR)

/* CAAM DID registers */
#define CAAM_JR0DID_MS (0x0010 + CAAM_BASE_ADDR)
#define CAAM_JR0DID_LS (0x0014 + CAAM_BASE_ADDR)
#define CAAM_JR1DID_MS (0x0018 + CAAM_BASE_ADDR)
#define CAAM_JR1DID_LS (0x001C + CAAM_BASE_ADDR)
#define CAAM_JR2DID_MS (0x0020 + CAAM_BASE_ADDR)
#define CAAM_JR2DID_LS (0x0024 + CAAM_BASE_ADDR)
#ifdef MACH_IMX8ULP
#define CAAM_JR3DID_MS (0x0028 + CAAM_BASE_ADDR)
#define CAAM_JR3DID_LS (0x002C + CAAM_BASE_ADDR)
#endif

#ifdef MACH_IMX8ULP
/* CAAM input ring base address register */
#define CAAM_IRBAR_JR0 (0x1004 + CAAM_BASE_ADDR)
#define CAAM_IRBAR_JR1 (0x2004 + CAAM_BASE_ADDR)
#define CAAM_IRBAR_JR2 (0x3004 + CAAM_BASE_ADDR)
#define CAAM_IRBAR_JR3 (0x4004 + CAAM_BASE_ADDR)

/* CAAM output ring base address register */
#define CAAM_ORBAR_JR0 (0x1024 + CAAM_BASE_ADDR)
#define CAAM_ORBAR_JR1 (0x2024 + CAAM_BASE_ADDR)
#define CAAM_ORBAR_JR2 (0x3024 + CAAM_BASE_ADDR)
#define CAAM_ORBAR_JR3 (0x4024 + CAAM_BASE_ADDR)

/* CAAM input ring size register */
#define CAAM_IRSR_JR0 (0x100C + CAAM_BASE_ADDR)
#define CAAM_IRSR_JR1 (0x200C + CAAM_BASE_ADDR)
#define CAAM_IRSR_JR2 (0x300C + CAAM_BASE_ADDR)
#define CAAM_IRSR_JR3 (0x400C + CAAM_BASE_ADDR)

/* CAAM output ring size register */
#define CAAM_ORSR_JR0 (0x102C + CAAM_BASE_ADDR)
#define CAAM_ORSR_JR1 (0x202C + CAAM_BASE_ADDR)
#define CAAM_ORSR_JR2 (0x302C + CAAM_BASE_ADDR)
#define CAAM_ORSR_JR3 (0x402C + CAAM_BASE_ADDR)
#endif

#ifdef MACH_IMX8Q
/* imx8q Job Ring 2 registers */
#define CAAM_IRBAR (0x30004 + CAAM_BASE_ADDR)
#define CAAM_IRSR (0x3000c + CAAM_BASE_ADDR)
#define CAAM_IRJAR (0x3001c + CAAM_BASE_ADDR)
#define CAAM_ORBAR (0x30024 + CAAM_BASE_ADDR)
#define CAAM_ORSR (0x3002c + CAAM_BASE_ADDR)
#define CAAM_ORSFR (0x3003c + CAAM_BASE_ADDR)
#define CAAM_ORJRR (0x30034 + CAAM_BASE_ADDR)
#define CAAM_JRINTR (0x3004C + CAAM_BASE_ADDR)
#define CAAM_JRCFGR_MS (0x30050 + CAAM_BASE_ADDR)
#define CAAM_JRCFGR_LS (0x30054 + CAAM_BASE_ADDR)
#define CAAM_JRCR (0x3006C + CAAM_BASE_ADDR)
#elif defined(MACH_IMX8ULP)
/* imx8ulp Job Ring 3 registers */
#define CAAM_IRBAR (0x4004 + CAAM_BASE_ADDR)
#define CAAM_IRSR (0x400c + CAAM_BASE_ADDR)
#define CAAM_IRJAR (0x401c + CAAM_BASE_ADDR)
#define CAAM_ORBAR (0x4024 + CAAM_BASE_ADDR)
#define CAAM_ORSR (0x402c + CAAM_BASE_ADDR)
#define CAAM_ORJRR (0x4034 + CAAM_BASE_ADDR)
#define CAAM_ORSFR (0x403c + CAAM_BASE_ADDR)
#define CAAM_JRINTR (0x404C + CAAM_BASE_ADDR)
#define CAAM_JRCFGR_MS (0x4050 + CAAM_BASE_ADDR)
#define CAAM_JRCFGR_LS (0x4054 + CAAM_BASE_ADDR)
#define CAAM_JRCR (0x406C + CAAM_BASE_ADDR)
#define CAAM_JRMIDR (0x0028 + CAAM_BASE_ADDR)
#define CAAM_JRLIDR (0x002c + CAAM_BASE_ADDR)
#elif defined(MACH_IMX8MQ) || defined(MACH_IMX8MM) || defined(MACH_IMX8MP)
/* imx8m Job Ring 1 registers */
#define CAAM_IRBAR (0x2004 + CAAM_BASE_ADDR)
#define CAAM_IRSR (0x200c + CAAM_BASE_ADDR)
#define CAAM_IRJAR (0x201c + CAAM_BASE_ADDR)
#define CAAM_ORBAR (0x2024 + CAAM_BASE_ADDR)
#define CAAM_ORSR (0x202c + CAAM_BASE_ADDR)
#define CAAM_ORJRR (0x2034 + CAAM_BASE_ADDR)
#define CAAM_ORSFR (0x203c + CAAM_BASE_ADDR)
#define CAAM_JRINTR (0x204C + CAAM_BASE_ADDR)
#define CAAM_JRCFGR_MS (0x2050 + CAAM_BASE_ADDR)
#define CAAM_JRCFGR_LS (0x2054 + CAAM_BASE_ADDR)
#define CAAM_JRCR (0x206C + CAAM_BASE_ADDR)
#define CAAM_JRMIDR (0x0018 + CAAM_BASE_ADDR)
#define CAAM_JRLIDR (0x001c + CAAM_BASE_ADDR)
#endif

/* State Handle */
#define BS_ALGO_RNG_SH            (4)
#define BM_ALGO_RNG_SH            (0x3 << BS_ALGO_RNG_SH)
#define ALGO_RNG_SH(id)           (((id) << BS_ALGO_RNG_SH) & BM_ALGO_RNG_SH)

/* Secure Key */
#define BS_ALGO_RNG_SK            (12)
#define BM_ALGO_RNG_SK            BIT(BS_ALGO_RNG_SK)

/* State */
#define BS_ALGO_RNG_AS            (2)
#define BM_ALGO_RNG_AS            (0x3UL << BS_ALGO_RNG_AS)
#define ALGO_RNG_GENERATE         (0x0UL << BS_ALGO_RNG_AS)
#define ALGO_RNG_INSTANTIATE      BIT(BS_ALGO_RNG_AS)

#define CAAM_HDR_CTYPE            (0x16UL << 27)
#define CAAM_HDR_ONE              BIT(23)
#define CAAM_HDR_START_INDEX(x)   (((x) & 0x3F) << 16)
#define CAAM_HDR_DESCLEN(x)       ((x) & 0x3F)
#define CAAM_PROTOP_CTYPE         (0x10UL << 27)

/* Prediction Resistance */
#define ALGO_RNG_PR               BIT(1)
#define CAAM_C1_RNG               ((0x50UL << 16) | (2UL << 24))

#define BS_JUMP_LOCAL_OFFSET      (0)
#define BM_JUMP_LOCAL_OFFSET      (0xFFUL << BS_JUMP_LOCAL_OFFSET)

#define CAAM_C1_JUMP              ((0x14UL << 27) | (1UL<< 25))
#define CAAM_JUMP_LOCAL           (0 << 20)
#define CAAM_JUMP_TST_ALL_COND_TRUE (0 << 16)
#define CAAM_JUMP_OFFSET(off)     (((off) << BS_JUMP_LOCAL_OFFSET) & BM_JUMP_LOCAL_OFFSET)

#define CAAM_C0_LOAD_IMM          ((0x2UL << 27) | (1UL << 23))
#define CAAM_DST_CLEAR_WRITTEN    (0x8UL << 16)

#define RNG_DESC_SH0_SIZE   (ARRAY_SIZE(rng_inst_sh0_desc))
#define RNG_DESC_SH1_SIZE   (ARRAY_SIZE(rng_inst_sh1_desc))
#define RNG_DESC_KEYS_SIZE  (ARRAY_SIZE(rng_inst_load_keys))
#define RNG_DESC_MAX_SIZE   (RNG_DESC_SH0_SIZE + RNG_DESC_SH1_SIZE + RNG_DESC_KEYS_SIZE)

#define JRCFG_LS_IMSK 0x00000001
#define JOB_RING_STS (0xFUL << 28)
#define RDSTA_IF0        (1)
#define RDSTA_IF1        (2)
#define RDSTA_SKVN (1UL << 30)
#define RTMCTL_PGM (1UL << 16)
#define RTMCTL_ERR (1UL << 12)
#define RTMCTL_ACC       BIT(5)
#define RTMCTL_FCT_FAIL  BIT(8)
#define RNG_TRIM_OSC_DIV 0
#define RNG_TRIM_ENT_DLY 3200

#endif
