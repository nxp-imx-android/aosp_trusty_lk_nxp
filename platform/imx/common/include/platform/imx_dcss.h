#ifndef __IMX_DCSS_H__
#define __IMX_DCSS_H__

#define CTXLD_DB_CTX_ENTRIES       1024/* max 65536 */
#define CTXLD_SB_LP_CTX_ENTRIES    10240/* max 65536 */
#define CTXLD_SB_HP_CTX_ENTRIES    20000/* max 65536 */
#define CTXLD_SB_CTX_ENTRIES    (CTXLD_SB_LP_CTX_ENTRIES + \
                                 CTXLD_SB_HP_CTX_ENTRIES)

#define SYSCALL_PLATFORM_FD_DCSS 0x9
#define DCSS_ENABLE_SECURE_CTXLD_BUFFER 0x00000001
#define DCSS_SET_SECUREUI_PARAMS 0x00000002

#define DCSS_CTXLD_DB_BASE_ADDR    0x10
#define DCSS_CTXLD_DB_COUNT    0x14
#define DCSS_CTXLD_SB_BASE_ADDR    0x18
#define DCSS_CTXLD_SB_COUNT    0x1C
#define   SB_HP_COUNT_POS     0
#define   SB_HP_COUNT_MASK    0xffff
#define   SB_LP_COUNT_POS     16
#define   SB_LP_COUNT_MASK    0xffff0000
#define DCSS_AHB_ERR_ADDR     0x20

#define CTX_ITEM_SIZE                   sizeof(struct dcss_ctxld_item)

#define   CTXLD_ENABLE         (1<<1)

#define   TC_Y_POS   16

enum dcss_ctxld_ctx_type {
    CTX_DB,
    CTX_SB_HP, /* high-priority */
    CTX_SB_LP, /* low-priority  */
};

enum dcss_reg_type {
    DPR,
    BLKCTL,
    CTXLD,
    DTG,
    RDSRC,
    WRSCL,
    SCALER,
    SS,
    DEC400D,
    HDR10,
    DTRC,
};

enum ctxld_buffer_type {
    NONE,
    FROUNT,
    BACKGROUND,
};

enum ctxld_operation_type {
    CTXLD_BUFFER_UPDATE = 0,
    CTXLD_BUFFER_SIZE_UPDATE,
};

struct dcss_msg {
    uint32_t enable;
};
/**secureui_params
 *@x: the x coordinate of the display position.
 *@y: the y coordinate of the display position.
 *@w: the witdh of secure UI.
 *@h: the height of secure UI.
**/
struct secureui_params {
    uint32_t x;
    uint32_t y;
    uint32_t w;
    uint32_t h;
};

struct dtg_dis_ulc {
    uint32_t dis_ulc_x;
    uint32_t dis_ulc_y;
};

#endif

