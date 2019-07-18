#include <dev/uart.h>
#include <kernel/thread.h>
#include <platform/debug.h>
#include <lib/sm/smcall.h>
#include <lib/sm.h>
#include <lk/init.h>
#include <imx-regs.h>
#include <reg.h>

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

#define SNVS_LPCR_SRTC_ENV      (1 << 0)
#define SNVS_LPCR_LPTA_EN       (1 << 1)
#define SNVS_LPCR_LPWUI_EN      (1 << 3)
#define SNVS_LPCR_DEP_EN        (1 << 5)
#define SNVS_LPCR_TERN_OFF_POW  (0x60)
#define SNVS_LPCR_BTN_PRESS_TIME (0x30000)

static long snvs_regs_op(smc32_args_t* args) {
    u32 target = args->params[0];
    u32 op = args->params[1];
    u32 val = args->params[2];

    if (op == OPT_READ) {
        switch (target) {
        case SNVS_LPCR:
        case SNVS_LPSR:
        case SNVS_LPSRTCMR:
        case SNVS_LPSRTCLR:
        case SNVS_LPTAR:
        case SNVS_LPPGDR:
        case SNVS_HPSR_REG:
                return *REG32(SNVS_RTC_BASE + target);
            default:
                return 0;
        }
    }

    if (op == OPT_WRITE) {
        switch (target) {
        case SNVS_LPSR:
        case SNVS_LPSRTCMR:
        case SNVS_LPSRTCLR:
        case SNVS_LPTAR:
        case SNVS_LPPGDR:
        case SNVS_HPSR_REG:
            *REG32(SNVS_RTC_BASE + target) = val;
            default:
                return 0;
        }
    }
    return 0;
}

static long snvs_lpcr_op(smc32_args_t* args) {
    u32 target = args->params[0];
    u32 enable = args->params[1];
    u32 val = *REG32(SNVS_RTC_BASE + SNVS_LPCR);
    if (enable)
        val = val | target;
    else
        val = val & (~target);
    switch (target) {
        case SNVS_LPCR_SRTC_ENV:
        case SNVS_LPCR_LPTA_EN:
        case SNVS_LPCR_LPWUI_EN:
        case SNVS_LPCR_DEP_EN:
	case SNVS_LPCR_TERN_OFF_POW:
	case SNVS_LPCR_BTN_PRESS_TIME:
            *REG32(SNVS_RTC_BASE + SNVS_LPCR) = val;
        default:
            return 0;
    }
    return 0;
}

static long snvs_fastcall(smc32_args_t* args) {

    if (args->smc_nr == SMC_SNVS_REGS_OP) {
        return snvs_regs_op(args);
    }

    if (args->smc_nr == SMC_SNVS_LPCR_OP) {
        return snvs_lpcr_op(args);
    }
    return 0;
}

static smc32_entity_t snvs_entity = {
    .fastcall_handler = snvs_fastcall,
};

void snvs_smcall_init(uint level) {
    sm_register_entity(SMC_ENTITY_SNVS_RTC, &snvs_entity);
}

LK_INIT_HOOK(snvs_driver, snvs_smcall_init, LK_INIT_LEVEL_PLATFORM);
