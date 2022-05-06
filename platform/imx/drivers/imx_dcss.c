#include <debug.h>
#include <err.h>
#include <kernel/vm.h>
#include <lib/trusty/sys_fd.h>
#include <lib/trusty/trusty_app.h>
#include <lk/init.h>
#include <mm.h>
#include <stdio.h>
#include <string.h>
#include <trace.h>
#include <platform/imx_csu.h>
#include <platform/imx_dcss.h>
#include <imx-regs.h>
#include <reg.h>
#include <lib/sm/smcall.h>
#include <lib/sm.h>

#define DRIVER_FD SYSCALL_PLATFORM_FD_DCSS
#define CHECK_FD(x) \
        do { if(x!=DRIVER_FD) return ERR_BAD_HANDLE; } while (0)

#define SMC_ENTITY_IMX_DCSS_OPT 56
#define SMC_IMX_DCSS_ECHO SMC_FASTCALL_NR(SMC_ENTITY_IMX_DCSS_OPT, 0)
#define SMC_IMX_DCSS_ALLOC_BUFFER SMC_FASTCALL_NR(SMC_ENTITY_IMX_DCSS_OPT, 1)
#define SMC_IMX_DCSS_BUFFER_WRITE SMC_FASTCALL_NR(SMC_ENTITY_IMX_DCSS_OPT, 2)
#define SMC_IMX_DCSS_REG  SMC_FASTCALL_NR(SMC_ENTITY_IMX_DCSS_OPT, 3)
#define SMC_IMX_DCSS_CTXLD_REG SMC_FASTCALL_NR(SMC_ENTITY_IMX_DCSS_OPT, 4)
#define SMC_IMX_DCSS_IRQ_REG SMC_FASTCALL_NR(SMC_ENTITY_IMX_DCSS_OPT, 5)
#define SMC_IMX_DCSS_IRQ_ECHO SMC_FASTCALL_NR(SMC_ENTITY_IMX_DCSS_OPT, 6)
#define SMC_IMX_DCSS_RELEASE_BUFFER SMC_FASTCALL_NR(SMC_ENTITY_IMX_DCSS_OPT, 7)

static bool tee_ctrl_dcss = false;
static uint32_t last_tee_fb_addr = 0x0;
static uint32_t g_db_size;
static uint32_t g_sb_size;
static uint32_t secure_flag = 0;
struct dcss_ctxld_item {
    u32 val;
    u32 ofs;
};

struct dcss_ctxld_item *db[2];
struct dcss_ctxld_item *sb_hp[2];
struct dcss_ctxld_item *sb_lp[2];
struct dcss_ctxld_item *secure_db[2];
struct dcss_ctxld_item *secure_sb_hp[2];
struct dcss_ctxld_item *secure_sb_lp[2];
void *linux_db[2];
void *linux_sb_hp[2];
void *linux_sb_lp[2];

paddr_t db_paddr[2], sb_paddr[2];
paddr_t linux_db_paddr[2], linux_sb_paddr[2];
paddr_t secure_db_paddr[2], secure_sb_paddr[2];
u16 ctx_size[2][3];
static u16 dcss_ctxld_ctx_size[3] = {
    CTXLD_DB_CTX_ENTRIES,
    CTXLD_SB_HP_CTX_ENTRIES,
    CTXLD_SB_LP_CTX_ENTRIES
};

static u32 g_curr_ctx = 0;
//Prevents Secure Memory from being written to the following registers in Secure mode.
static u32 secure_addr_regs[] = {0x32E23010, 0x32E23018, 0x32E23020,
                                 0x32E15900, 0x32E15980,
                                 0x32E16000, 0x32E16004, 0x32E16008, 0x32E1600C,
                                 0x32E17000, 0x32E17004, 0x32E17008, 0x32E1700C,
                                 0x32E190C0, 0x32E19110, 0x32E1A0C0, 0x32E1A110,
                                 0x32E1C080, 0x32E1C048, 0x32E1C050, 0x32E1C058,
                                 0x32E24010,
                                 0x32E21010, 0x32E22010};

static u32 secure_reg_range[3][2] = {{0x32E18000, 0x32E19000}, {0x32E1C000, 0x32E1C400},
                                     {0x32E00000, 0x32E04000}};
static u32 secure_reg_range_ofs[3][2] = {{0x18000, 0x19000}, {0x1C000, 0x1C400},
                                         {0x0, 0x4000}};


static void wait_for_dcss_irq() {
    uint32_t timeout = 0x00FFFFFF;
    uint32_t val;

    while (timeout) {
        timeout--;
        val = readl((uint8_t*)DCSS_BASE_VIRT + 0x23000);
        if (val & CTXLD_IRQ_COMPLETION &&
            !(val & CTXLD_ENABLE)) {
            return;
        }
    }
}

static long dcss_writel(u32 value, u32 reg) {
    int i;
    if ((((IMX_DCSS_REG_RANGE1_MIN + reg) >= IMX_DCSS_REG_RANGE1_MIN) && ((IMX_DCSS_REG_RANGE1_MIN + reg) < IMX_DCSS_REG_RANGE1_MAX))
        || (((IMX_DCSS_REG_RANGE1_MIN + reg) >= IMX_DCSS_REG_RANGE2_MIN) && ((IMX_DCSS_REG_RANGE1_MIN + reg) < IMX_DCSS_REG_RANGE2_MAX))) {
        if (secure_flag) {
            for (i = 0; i < (int)(sizeof(secure_addr_regs)/sizeof(secure_addr_regs[0])); i++) {
                if (((IMX_DCSS_REG_RANGE1_MIN + reg) == secure_addr_regs[i])) {
                    /* if the reg is ctxld_db or ctxld_sb buffer, will judge whether it is db_paddr,
                     * sb_paddr or 0x0, if the value is, will write into reg, or return 0*/
                    if ((((IMX_DCSS_REG_RANGE1_MIN + reg) == 0x32E23010) && ((value == db_paddr[0]) || (value == db_paddr[1]) || (value == 0))) ||
                        (((IMX_DCSS_REG_RANGE1_MIN + reg) == 0x32E23018) && ((value == sb_paddr[0]) || (value == sb_paddr[1]) || (value == 0)))) {
                        writel(value, (uint8_t* )DCSS_BASE_VIRT + reg);
                        return 0;
                    }
                    if ((value >= MEMBASE) && (value < MEMBASE + MEMSIZE))
                        return 0;
                }
            }
        }

        if (tee_ctrl_dcss) {
            if (((reg < secure_reg_range_ofs[0][1]) && (reg >= secure_reg_range_ofs[0][0]))
                || ((reg < secure_reg_range_ofs[1][1]) && (reg >= secure_reg_range_ofs[1][0]))
                || ((reg < secure_reg_range_ofs[2][1]) && (reg >= secure_reg_range_ofs[2][0]))) {
                    return 0;
            }
        }

        writel(value, (uint8_t* )DCSS_BASE_VIRT + reg);
    } else {
        printf("out of dcss register range\n");
    }
    return 0;
}

static int imx_init_secureui(u32 ctxId, u32 val, u32 reg) {
    u32 curr_ctx = g_curr_ctx;
    struct dcss_ctxld_item *ctx[] = {
        [CTX_DB] = db[curr_ctx],
        [CTX_SB_HP] = sb_hp[curr_ctx],
        [CTX_SB_LP] = sb_lp[curr_ctx]
    };

    u32 item_idx = ctx_size[curr_ctx][ctxId];
    if (item_idx + 1 > dcss_ctxld_ctx_size[ctxId]) {
        return -1;
    }

    ctx[ctxId][item_idx].val = val;
    ctx[ctxId][item_idx].ofs = reg;
    ctx_size[curr_ctx][ctxId] += 1;
    return 0;
}

static void init_dtg_ch1_regs() {
    imx_init_secureui(CTX_DB, 0x2c00bf, 0x00020008);
    imx_init_secureui(CTX_DB, 0x2c00bf, 0x00020010);
    imx_init_secureui(CTX_DB, 0x464083f, 0x00020014);
    imx_init_secureui(CTX_DB, 0x0, 0x0002002c);
}
static void init_dpr_ch1_regs() {
    imx_init_secureui(CTX_SB_HP, 0xc6203, 0x00018050);
    imx_init_secureui(CTX_SB_HP, 0x1e000000, 0x00018070);
    imx_init_secureui(CTX_SB_HP, 0x2, 0x00018090);
    imx_init_secureui(CTX_SB_HP, 0x780, 0x000180a0);

    imx_init_secureui(CTX_SB_HP, 0x438, 0x000180b0);
    imx_init_secureui(CTX_SB_HP, 0x280, 0x000180f0);
    imx_init_secureui(CTX_SB_HP, 0xf0, 0x00018100);
    imx_init_secureui(CTX_SB_HP, 0x38, 0x00018200);
}
static void init_scaler_ch1_regs() {
    imx_init_secureui(CTX_SB_HP, 0x10, 0x0001c000);
    imx_init_secureui(CTX_SB_HP, 0x20000000, 0x0001c004);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0001c008);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0001c00c);
    imx_init_secureui(CTX_SB_HP, 0x2, 0x0001c010);
    imx_init_secureui(CTX_SB_HP, 0x2, 0x0001c014);
    imx_init_secureui(CTX_SB_HP, 0x437077f, 0x0001c018);
    imx_init_secureui(CTX_SB_HP, 0x437077f, 0x0001c01c);
    imx_init_secureui(CTX_SB_HP, 0x437077f, 0x0001c020);
    imx_init_secureui(CTX_SB_HP, 0x437077f, 0x0001c024);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0001c048);
    imx_init_secureui(CTX_SB_HP, 0x2000, 0x0001c04c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0001c050);
    imx_init_secureui(CTX_SB_HP, 0x2000, 0x0001c054);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0001c058);
    imx_init_secureui(CTX_SB_HP, 0x2000, 0x0001c05c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0001c060);
    imx_init_secureui(CTX_SB_HP, 0x2000, 0x0001c064);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0001c080);
}
static void init_hdr10_ch1_regs() {
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00000000);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00001000);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00002000);
    imx_init_secureui(CTX_SB_HP, 0x8000, 0x00003000);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003004);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003008);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0000300c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003010);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003014);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003018);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0000301c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003020);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003024);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003028);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0000302c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003030);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003034);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003038);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0000303c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003040);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003044);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003048);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0000304c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003050);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003054);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003058);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0000305c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003060);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003064);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003068);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0000306c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003070);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003074);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003078);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0000307c);
    imx_init_secureui(CTX_SB_HP, 0x3, 0x00003080);
    imx_init_secureui(CTX_SB_HP, 0x8000, 0x00003800);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003804);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003808);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0000380c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003810);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003814);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003818);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0000381c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003820);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003824);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003828);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0000382c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003830);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003834);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003838);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0000383c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003840);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003844);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003848);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0000384c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003850);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003854);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003858);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0000385c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003860);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003864);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003868);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0000386c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003870);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003874);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00003878);
}
static void init_ss_regs() {
    imx_init_secureui(CTX_SB_HP, 0x1, 0x0001b000);
    imx_init_secureui(CTX_SB_HP, 0x4640897, 0x0001b010);
    imx_init_secureui(CTX_SB_HP, 0x802b0897, 0x0001b020);
    imx_init_secureui(CTX_SB_HP, 0x80080003, 0x0001b030);
    imx_init_secureui(CTX_SB_HP, 0x802d00bf, 0x0001b040);
    imx_init_secureui(CTX_SB_HP, 0x464083f, 0x0001b050);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0001b060);
    imx_init_secureui(CTX_SB_HP, 0x41614161, 0x0001b070);
    imx_init_secureui(CTX_SB_HP, 0x3ff0000, 0x0001b080);
    imx_init_secureui(CTX_SB_HP, 0x3ff0000, 0x0001b090);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x0001b0a0);
}

static void init_dec400d_ch1_regs() {
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015024);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015028);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015098);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x000150a8);
    imx_init_secureui(CTX_SB_HP, 0x210a, 0x00015b00);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b04);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b08);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b0c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b10);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b14);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b18);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b1c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b20);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b24);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b28);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b2c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b30);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b34);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b38);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b3c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b40);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b44);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b48);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b4c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b50);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b54);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b58);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b5c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b60);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b64);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b68);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b6c);
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015b70);

    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015900); // if enable tile will write framebuffer addr into this.
    imx_init_secureui(CTX_SB_HP, 0x0, 0x00015980);
}

static int imx_liux_dcss_ctxld(struct smc32_args* args) {

    u32 curr_ctx = args->params[0];

    u32 sb_hp_cnt, sb_lp_cnt, db_cnt;
    u32 db_base, sb_base, sb_count;

    sb_hp_cnt = ctx_size[curr_ctx][CTX_SB_HP];
    sb_lp_cnt = ctx_size[curr_ctx][CTX_SB_LP];
    db_cnt = ctx_size[curr_ctx][CTX_DB];

    if (sb_lp_cnt &&
        sb_lp[curr_ctx] != sb_hp[curr_ctx] + sb_hp_cnt) {
        struct dcss_ctxld_item *sb_lp_adjusted;

        sb_lp_adjusted = sb_hp[curr_ctx] + sb_hp_cnt;

        memcpy(sb_lp_adjusted, sb_lp[curr_ctx],
               sb_lp_cnt * CTX_ITEM_SIZE);
    }
    if (secure_flag) {
        arch_clean_cache_range((addr_t)(db[curr_ctx]), g_db_size);
        arch_clean_cache_range((addr_t)(sb_hp[curr_ctx]), g_sb_size);
    }

    db_base = db_cnt ? db_paddr[curr_ctx] : 0;

    dcss_writel(db_base, CTXLD_OFS + DCSS_CTXLD_DB_BASE_ADDR);
    dcss_writel(db_cnt, CTXLD_OFS + DCSS_CTXLD_DB_COUNT);

    if (sb_hp_cnt)
        sb_count = ((sb_hp_cnt << SB_HP_COUNT_POS) & SB_HP_COUNT_MASK) |
        ((sb_lp_cnt << SB_LP_COUNT_POS) & SB_LP_COUNT_MASK);
    else
        sb_count = (sb_lp_cnt << SB_HP_COUNT_POS) & SB_HP_COUNT_MASK;

    sb_base = sb_count ? sb_paddr[curr_ctx] : 0;

    dcss_writel(sb_base, CTXLD_OFS + DCSS_CTXLD_SB_BASE_ADDR);
    dcss_writel(sb_count, CTXLD_OFS + DCSS_CTXLD_SB_COUNT);

    return 0;
}

int32_t imx_dcss_secure_disp(uint32_t cmd, user_addr_t user_ptr) {
    struct csu_cfg_secure_disp_msg *msg = (struct csu_cfg_secure_disp_msg*) user_ptr;
    if (msg->enable) {
        printf("imx_dcss_secure_disp enable \n");
        tee_ctrl_dcss = true;

        wait_for_dcss_irq();
        g_curr_ctx ^= 1;
        last_tee_fb_addr = msg->paddr;
        init_dpr_ch1_regs();
        init_scaler_ch1_regs();
        init_hdr10_ch1_regs();
        init_dec400d_ch1_regs();
        init_dtg_ch1_regs();
        init_ss_regs();
        u32 width = 1920;
        u32 height = 1080;
        imx_init_secureui(CTX_SB_HP, width, 0x180a0); //width
        imx_init_secureui(CTX_SB_HP, height, 0x180b0); //height
        imx_init_secureui(CTX_SB_HP, ((width * 4) << 16), 0x18070);
        imx_init_secureui(CTX_SB_HP, last_tee_fb_addr, DCSS_DPR_FRAME_1P_BASE_ADDR);
        imx_init_secureui(CTX_SB_HP, 0, DCSS_DPR_FRAME_2P_BASE_ADDR);
        imx_init_secureui(CTX_SB_HP, 0x5, 0x00018000); //enable display

        // enable ctxld to flush the reg
        struct smc32_args arg;
        arg.params[0] = g_curr_ctx;
        imx_liux_dcss_ctxld(&arg);
        dcss_writel(1, DCSS_CTXLD_CONTROL_STATUS_SET);
        g_curr_ctx ^= 1;
        ctx_size[g_curr_ctx][CTX_DB] = 0;
        ctx_size[g_curr_ctx][CTX_SB_HP] = 0;
        ctx_size[g_curr_ctx][CTX_SB_LP] = 0;
        // end

     } else {
        printf("imx_dcss_secure_disp disable \n");
        tee_ctrl_dcss = false;
    }

    return 0;
}

static void write_irq(u32 value, u32 reg) {
    if (((IMX_DCSS_IRQSTEER_RANGE_MIN + reg) >= IMX_DCSS_IRQSTEER_RANGE_MIN) &&
        ((IMX_DCSS_IRQSTEER_RANGE_MIN + reg) < IMX_DCSS_IRQSTEER_RANGE_MAX)) {
        writel(value, (uint8_t*)DCSS_IRQ_VIRT + reg);
    } else {
        printf("not in of dcss irq regs range\n");
    }
}

static long imx_linux_dcss_reg(struct smc32_args* args) {
    u32 target = args->params[0];
    enum dcss_reg_type reg_type = args->params[1] & 0x0f;
    u8 ch = (args->params[1] & 0xf0) >> 4;
    u32 val = args->params[2];
    switch (reg_type) {
        case DPR:
            dcss_writel(val, DPR_OFS + ch * DPR_CHAN_OFS + target);
            break;
        case BLKCTL:
            dcss_writel(val, BLKCTL_OFS + target);
            break;
        case CTXLD:
            dcss_writel(val, CTXLD_OFS + target);
            break;
        case DTG:
            dcss_writel(val, DTG_OFS + target);
            break;
        case RDSRC:
            dcss_writel(val, RDSRC_OFS + target);
            break;
        case WRSCL:
            dcss_writel(val, WRSCL_OFS + target);
            break;
        case SCALER:
            dcss_writel(val, SCALER_OFS + ch * SCALER_CHAN_OFS + target);
            break;
        case SS:
            dcss_writel(val, SS_OFS + target);
            break;
        case DEC400D:
            dcss_writel(val, DEC400D_OFS + target);
            break;
        case HDR10:
            dcss_writel(val, HDR10_OFS + ch * HDR10_CHAN_OFS + target);
            break;
        case DTRC:
            dcss_writel(val, DTRC_OFS + ch * DTRC_CHAN_OFS + target);
            break;
    }
    return 0;
}

static int imx_linux_dcss_buffer_alloc(struct smc32_args* args) {
    int i = 0;
    struct dcss_ctxld_item *alloc_buf;
    u32 option = args->params[0];
    uint32_t db_size = round_up(CTXLD_DB_CTX_ENTRIES * sizeof(struct dcss_ctxld_item), PAGE_SIZE);
    uint32_t sb_size = round_up(CTXLD_SB_CTX_ENTRIES * sizeof(struct dcss_ctxld_item), PAGE_SIZE);
    g_db_size = db_size;
    g_sb_size = sb_size;
    if (option == NONE) {
        for (i = 0; i < 2; i++) {
             alloc_buf = memalign(PAGE_SIZE, db_size);
             if (!alloc_buf) {
                 printf("alloc ctxld db_buffer failed!!\n");
                 return -1;
             }
             secure_db[i] = alloc_buf;
             secure_db_paddr[i] = vaddr_to_paddr(alloc_buf);
             alloc_buf = memalign(PAGE_SIZE, sb_size);
             if (!alloc_buf) {
                 printf("alloc ctxld sb_buffer failed!!\n");
                 return -1;
             }
             secure_sb_hp[i] = alloc_buf;
             secure_sb_lp[i] = alloc_buf + CTXLD_SB_HP_CTX_ENTRIES;
             secure_sb_paddr[i] = vaddr_to_paddr(alloc_buf);
        }
    } else if (option == FROUNT) {
        int ret = vmm_alloc_physical(vmm_get_kernel_aspace(), "db_0", g_db_size, &(linux_db[0]), 0, args->params[1], 0,
                       ARCH_MMU_FLAG_UNCACHED_DEVICE);
        if (ret) {
            printf("mmap linux db buffer failed !ret=%d db_paddr=0x%08x\n",ret, args->params[1]);
        }
        ret = vmm_alloc_physical(vmm_get_kernel_aspace(), "sb_0", g_sb_size, &(linux_sb_hp[0]), 0, args->params[2], 0,
                       ARCH_MMU_FLAG_UNCACHED_DEVICE);
        if (ret) {
            printf("mmap linux sb buffer failed !ret=%d sb_paddr=0x%08x\n",ret, args->params[2]);
        }
        linux_sb_lp[0] = linux_sb_hp[0] + CTXLD_SB_HP_CTX_ENTRIES;
        linux_db_paddr[0] = args->params[1];
        linux_sb_paddr[0] = args->params[2];
        db[0] = (struct dcss_ctxld_item*)linux_db[0];
        sb_hp[0] = (struct dcss_ctxld_item*)linux_sb_hp[0];
        sb_lp[0] = (struct dcss_ctxld_item*)linux_sb_lp[0];
        db_paddr[0] = linux_db_paddr[0];
        sb_paddr[0] = linux_sb_paddr[0];
    } else if (option == BACKGROUND) {
        int ret = vmm_alloc_physical(vmm_get_kernel_aspace(), "db_1", g_db_size, &(linux_db[1]), 0, args->params[1], 0,
                        ARCH_MMU_FLAG_UNCACHED_DEVICE);
        if (ret) {
            printf("mmap linux db[1] buffer failed !ret=%d db_paddr=0x%08x\n",ret, args->params[1]);
        }
        ret = vmm_alloc_physical(vmm_get_kernel_aspace(), "sb_1", g_sb_size, &(linux_sb_hp[1]), 0, args->params[2], 0,
                       ARCH_MMU_FLAG_UNCACHED_DEVICE);
        if (ret) {
            printf("mmap linux sb[1] buffer failed !ret=%d sb_paddr=0x%08x\n",ret, args->params[2]);
        }
        linux_sb_lp[1] = linux_sb_hp[1] + CTXLD_SB_HP_CTX_ENTRIES;
        linux_db_paddr[1] = args->params[1];
        linux_sb_paddr[1] = args->params[2];
        db[1] = (struct dcss_ctxld_item*)linux_db[1];
        sb_hp[1] = (struct dcss_ctxld_item*)linux_sb_hp[1];
        sb_lp[1] = (struct dcss_ctxld_item*)linux_sb_lp[1];
        db_paddr[1] = linux_db_paddr[1];
        sb_paddr[1] = linux_sb_paddr[1];
    } else {
        printf("alloc ctxld buffer command is invalid\n");
        return -1;
    }
    return 0;
}

static int imx_linux_dcss_release_buffer() {
    for (int i = 0; i < 2; i++) {
        free(secure_db[i]);
        free(secure_sb_hp[i]);
        secure_db[i] = NULL;
        secure_sb_hp[i] = NULL;
    }
    return 0;
}
static int imx_linux_dcss_buffer_write(struct smc32_args* args) {
    u32 curr_ctx = args->params[0] & 0x0f;
    g_curr_ctx = curr_ctx;
    u32 ctx_id = (args->params[0] & 0xf0) >> 4;
    u32 option = (args->params[0] & 0xf00) >> 8;
    u32 val = args->params[1];
    u32 reg_ofs = args->params[2];
    struct dcss_ctxld_item *ctx[] = {
        [CTX_DB] = db[curr_ctx],
        [CTX_SB_HP] = sb_hp[curr_ctx],
        [CTX_SB_LP] = sb_lp[curr_ctx]
    };

    int item_idx, i;
    switch (option) {
        case CTXLD_BUFFER_UPDATE:
            if (((reg_ofs >= IMX_DCSS_REG_RANGE1_MIN) && (reg_ofs < IMX_DCSS_REG_RANGE1_MAX))
                || ((reg_ofs >= IMX_DCSS_REG_RANGE2_MIN) && (reg_ofs < IMX_DCSS_REG_RANGE2_MAX))) {
                if (tee_ctrl_dcss) {
                    if (((reg_ofs < secure_reg_range[0][1]) && (reg_ofs >= secure_reg_range[0][0]))
                        || ((reg_ofs < secure_reg_range[1][1]) && (reg_ofs >= secure_reg_range[1][0]))
                        || ((reg_ofs < secure_reg_range[2][1]) && (reg_ofs >= secure_reg_range[2][0]))) {
                        return 0;
                    }
                }

                if (secure_flag) {
                    for (i = 0; i < (int)(sizeof(secure_addr_regs)/sizeof(secure_addr_regs[0])); i++) {
                        if ((reg_ofs == secure_addr_regs[i]) && ((val >= MEMBASE) && (val < MEMBASE + MEMSIZE)))
                            return 0;
                    }
                }
            } else {
                printf("writting ctxld buffer out of dcss reg range \n");
                return 0;
            }
            item_idx = ctx_size[curr_ctx][ctx_id];
            if (item_idx + 1 > dcss_ctxld_ctx_size[ctx_id]) {
                return -1;
            }

            ctx[ctx_id][item_idx].val = val;
            ctx[ctx_id][item_idx].ofs = reg_ofs;
            ctx_size[curr_ctx][ctx_id] += 1;
            break;
        case CTXLD_BUFFER_SIZE_UPDATE:
            ctx_size[curr_ctx][ctx_id] = val;
            break;
        default:
            printf("buffer write invalid index\n");
    }
    return 0;
}

static int imx_linux_dcss_irqsteer(struct smc32_args* args) {
    u32 val = args->params[0];
    u32 ofs = args->params[1];
    write_irq(val, ofs);
    return 0;
}

static long imx_dcss_fastcall(struct smc32_args* args) {
    switch (args->smc_nr) {
        case SMC_IMX_DCSS_ECHO:
            return 0;
        case SMC_IMX_DCSS_REG:
            return imx_linux_dcss_reg(args);
        case SMC_IMX_DCSS_ALLOC_BUFFER:
            return imx_linux_dcss_buffer_alloc(args);
        case SMC_IMX_DCSS_BUFFER_WRITE:
            return imx_linux_dcss_buffer_write(args);
        case SMC_IMX_DCSS_CTXLD_REG:
            return imx_liux_dcss_ctxld(args);
        case SMC_IMX_DCSS_IRQ_ECHO:
            return 0;
        case SMC_IMX_DCSS_IRQ_REG:
            return imx_linux_dcss_irqsteer(args);
        case SMC_IMX_DCSS_RELEASE_BUFFER:
            return imx_linux_dcss_release_buffer();
    }
    return 0;
}

static int32_t switch_secure_ctxld_buffer(user_addr_t user_ptr) {
    struct dcss_msg *msg = (struct dcss_msg *)user_ptr;
    secure_flag = msg->enable;
    int i;
    if (secure_flag) {
        for(i = 0; i < 2; i++) {
            db[i] = secure_db[i];
            db_paddr[i] = secure_db_paddr[i];
            sb_hp[i] = secure_sb_hp[i];
            sb_lp[i] = secure_sb_lp[i];
            sb_paddr[i] = secure_sb_paddr[i];
            vmm_free_region(vmm_get_kernel_aspace(), (vaddr_t)linux_db[i]);
            vmm_free_region(vmm_get_kernel_aspace(), (vaddr_t)linux_sb_hp[i]);
        }

    }
    return 0;
}

static int32_t sys_dcss_ioctl(uint32_t fd, uint32_t cmd, user_addr_t user_ptr) {
    CHECK_FD(fd);
    switch (cmd) {
        case DCSS_ENABLE_SECURE_CTXLD_BUFFER:
            return switch_secure_ctxld_buffer(user_ptr);
    }
    return 0;
}

static struct smc32_entity imx_dcss_entity = {
    .fastcall_handler = imx_dcss_fastcall,
};

static const struct sys_fd_ops dcss_ops = {
    .ioctl = sys_dcss_ioctl,
};

void imx_dcss_smcall_init(uint level) {
    sm_register_entity(SMC_ENTITY_IMX_DCSS_OPT, &imx_dcss_entity);
}

void platform_init_dcss(uint level) {
    install_sys_fd_handler(SYSCALL_PLATFORM_FD_DCSS, &dcss_ops);
}

LK_INIT_HOOK(imx_dcss_ioctl, platform_init_dcss, LK_INIT_LEVEL_PLATFORM + 1);
LK_INIT_HOOK(imx_dcss_driver, imx_dcss_smcall_init, LK_INIT_LEVEL_PLATFORM);
