#include <dev/uart.h>
#include <kernel/thread.h>
#include <platform/debug.h>
#include <lib/sm/smcall.h>
#include <lib/sm.h>
#include <lk/init.h>
#include <imx-regs.h>
#include <trace.h>
#include <reg.h>

#define LOCAL_TRACE     0

#define SNVS_RTC_BASE (SNVS_VIRT_BASE)

#define SMC_ENTITY_SNVS_RTC 53
#define SMC_SNVS_PROBE SMC_FASTCALL_NR(SMC_ENTITY_SNVS_RTC, 0)
#define SMC_SNVS_REGS_OP SMC_FASTCALL_NR(SMC_ENTITY_SNVS_RTC, 1)
#define SMC_SNVS_LPCR_OP SMC_FASTCALL_NR(SMC_ENTITY_SNVS_RTC, 2)
#define OPT_READ 0x1
#define OPT_WRITE 0x2

#define SNVS_LP_OFFSET          0x34

#define SNVS_HPSR_REG           0x14
#define SNVS_LPCR               (0x04 + SNVS_LP_OFFSET)
#define SNVS_LPSR               (0x18 + SNVS_LP_OFFSET)
#define SNVS_LPSRTCMR           (0x1c + SNVS_LP_OFFSET)
#define SNVS_LPSRTCLR           (0x20 + SNVS_LP_OFFSET)
#define SNVS_LPTAR              (0x24 + SNVS_LP_OFFSET)
#define SNVS_LPPGDR             (0x30 + SNVS_LP_OFFSET)

#define SNVS_LPGPR2             (0x64 + SNVS_LP_OFFSET)
#define SNVS_LPGPR3             (0x68 + SNVS_LP_OFFSET)

#define SNVS_LPCR_SRTC_ENV      (1 << 0)
#define SNVS_LPCR_LPTA_EN       (1 << 1)
#define SNVS_LPCR_LPWUI_EN      (1 << 3)
#define SNVS_LPCR_DEP_EN        (1 << 5)
#define SNVS_LPCR_TERN_OFF_POW  (0x60)
#define SNVS_LPCR_BTN_PRESS_TIME (0x30000)

#define CNTR_TO_SECS_SH     15
#define SNVS_LPPGDR_INIT    0x41736166

#define dump_counter(counter) \
    do { \
        LTRACEF("counter: lpmr=0x%x  lplr=0x%x  lp_counter=0x%llx\n", counter.lpmr, counter.lplr, counter.lp_counter); \
        LTRACEF("counter: mask_lpmr=0x%x  mask_lplr=0x%x  mask=0x%llx\n", counter.mask_lpmr, counter.mask_lplr, counter.mask); \
        LTRACEF("counter: logic_mr=0x%x  logic_lr=0x%x  logic_counter=0x%llx\n", counter.logic_mr, counter.logic_lr, counter.logic_counter); \
    } while(0)

struct snvs_counter {
    uint32_t lpmr;
    uint32_t lplr;
    uint64_t lp_counter;
    uint32_t mask_lpmr;
    uint32_t mask_lplr;
    uint64_t mask;
    uint64_t logic_counter;
    uint32_t logic_mr;
    uint32_t logic_lr;
};

static void update_counter(struct snvs_counter *counter) {
    counter->lpmr = *REG32(SNVS_RTC_BASE + SNVS_LPSRTCMR);
    counter->lplr = *REG32(SNVS_RTC_BASE + SNVS_LPSRTCLR);
    counter->lp_counter = ((uint64_t)counter->lpmr << 32) | counter->lplr;
    counter->mask_lpmr = *REG32(SNVS_RTC_BASE + SNVS_LPGPR2);
    counter->mask_lplr = *REG32(SNVS_RTC_BASE + SNVS_LPGPR3);
    counter->mask = ((uint64_t)counter->mask_lpmr << 32) | counter->mask_lplr;
    counter->logic_counter = counter->lp_counter + counter->mask;
    counter->logic_mr = counter->logic_counter >> 32;
    counter->logic_lr = (uint32_t)(counter->logic_counter & 0xFFFFFFFF);
}

static void write_counter(struct snvs_counter *counter) {
    *REG32(SNVS_RTC_BASE + SNVS_LPGPR2) = counter->mask_lpmr;
    *REG32(SNVS_RTC_BASE + SNVS_LPGPR3) = counter->mask_lplr;
}

static long snvs_read_logic_mr(void) {
    struct snvs_counter counter;
    update_counter(&counter);

    dump_counter(counter);
    return counter.logic_mr;
}

static long snvs_read_logic_lr(void) {
    struct snvs_counter counter;
    update_counter(&counter);
    dump_counter(counter);

    return counter.logic_lr;
}

static long snvs_write_logic_mr(uint32_t val) {
    struct snvs_counter counter;
    update_counter(&counter);

    counter.logic_mr = val;
    counter.logic_counter = ((uint64_t)counter.logic_mr << 32) | counter.logic_lr;
    counter.mask = counter.logic_counter - counter.lp_counter;
    counter.mask_lpmr = counter.mask >> 32;
    counter.mask_lplr = (uint32_t)(counter.mask & 0xFFFFFFFF);

    write_counter(&counter);
    dump_counter(counter);

    return 0;

}

static long snvs_write_logic_lr(uint32_t val) {
    struct snvs_counter counter;
    update_counter(&counter);

    counter.logic_lr = val;
    counter.logic_counter = ((uint64_t)counter.logic_mr << 32) | counter.logic_lr;
    counter.mask = counter.logic_counter - counter.lp_counter;
    counter.mask_lpmr = counter.mask >> 32;
    counter.mask_lplr = (uint32_t)(counter.mask & 0xFFFFFFFF);

    write_counter(&counter);
    dump_counter(counter);

    return 0;
}

uint32_t monotonic_time_s(void) {
    struct snvs_counter counter;
    update_counter(&counter);
    uint32_t monotonic_time = (counter.lplr >> CNTR_TO_SECS_SH) | (counter.lpmr << (32 - CNTR_TO_SECS_SH));

    return monotonic_time;
}

static long snvs_write_logic_alarm(uint32_t val) {
    struct snvs_counter counter;
    update_counter(&counter);
    uint64_t alarm_64 = (uint64_t)val << CNTR_TO_SECS_SH;
    uint32_t lpta = (uint32_t)(((alarm_64 - counter.mask) >> CNTR_TO_SECS_SH) & 0xFFFFFFFF);

    *REG32(SNVS_RTC_BASE + SNVS_LPTAR) = lpta;
    dump_counter(counter);

    return 0;
}

static long snvs_read_logic_alarm(void) {
    struct snvs_counter counter;
    update_counter(&counter);
    uint32_t lpta = *REG32(SNVS_RTC_BASE + SNVS_LPTAR);

    uint64_t lpta_64 = (uint64_t)lpta << CNTR_TO_SECS_SH;
    uint32_t logic_lpta = (((lpta_64 + counter.mask) >> CNTR_TO_SECS_SH) & 0xFFFFFFFF);
    dump_counter(counter);

    return logic_lpta;
}

static long snvs_regs_op(struct smc32_args* args) {
    u32 target = args->params[0];
    u32 op = args->params[1];
    u32 val = args->params[2];

    if (op == OPT_READ) {
        switch (target) {
        case SNVS_LPSRTCMR:
            return snvs_read_logic_mr();
            break;
        case SNVS_LPSRTCLR:
            return snvs_read_logic_lr();
            break;
        case SNVS_LPTAR:
            return snvs_read_logic_alarm();
            break;
        case SNVS_LPCR:
        case SNVS_LPSR:
        case SNVS_LPPGDR:
        case SNVS_HPSR_REG:
             return *REG32(SNVS_RTC_BASE + target);
             break;
        default:
                return 0;
        }
    }

    if (op == OPT_WRITE) {
        switch (target) {
        case SNVS_LPSRTCMR:
            return snvs_write_logic_mr(val);
            break;
        case SNVS_LPSRTCLR:
            return snvs_write_logic_lr(val);
            break;
        case SNVS_LPTAR:
            return snvs_write_logic_alarm(val);
            break;
        case SNVS_LPSR:
        case SNVS_HPSR_REG:
             *REG32(SNVS_RTC_BASE + target) = val;
             return 0;
             break;
        default:
                return 0;
        }
    }
    return 0;
}

static long snvs_lpcr_op(struct smc32_args* args) {
    u32 target = args->params[0];
    u32 enable = args->params[1];
    u32 val = *REG32(SNVS_RTC_BASE + SNVS_LPCR);
    if (enable)
        val = val | target;
    else
        val = val & (~target);
    switch (target) {
        case SNVS_LPCR_LPTA_EN:
        case SNVS_LPCR_LPWUI_EN:
        case SNVS_LPCR_DEP_EN:
        case SNVS_LPCR_TERN_OFF_POW:
        case SNVS_LPCR_BTN_PRESS_TIME:
             *REG32(SNVS_RTC_BASE + SNVS_LPCR) = val;
             return 0;
             break;
        default:
            return 0;
    }
    return 0;
}

static long snvs_fastcall(struct smc32_args* args) {

    if (args->smc_nr == SMC_SNVS_REGS_OP) {
        return snvs_regs_op(args);
    }

    if (args->smc_nr == SMC_SNVS_LPCR_OP) {
        return snvs_lpcr_op(args);
    }
    return 0;
}

static struct smc32_entity snvs_entity = {
    .fastcall_handler = snvs_fastcall,
};

static void enable_srtc(void) {
    *REG32(SNVS_RTC_BASE + SNVS_LPPGDR) = SNVS_LPPGDR_INIT;
    u32 val = *REG32(SNVS_RTC_BASE + SNVS_LPCR);
    val |= SNVS_LPCR_SRTC_ENV;
    *REG32(SNVS_RTC_BASE + SNVS_LPCR) = val;
}

void snvs_smcall_init(uint level) {
    enable_srtc();
    sm_register_entity(SMC_ENTITY_SNVS_RTC, &snvs_entity);
}

LK_INIT_HOOK(snvs_driver, snvs_smcall_init, LK_INIT_LEVEL_PLATFORM);
