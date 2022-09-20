
#pragma once

#include <trusty_ipc.h>
#include <trusty_log.h>

__BEGIN_CDECLS

/* CSU initialization to be used by hwsecure TA */
int init_csu(void);
/* RDC initialization to be used by hwsecure TA */
int init_rdc(void);

/* Configure CSU to make LCDIF work in secure mode */
int set_lcdif_secure(uint32_t cmd);

/* Configure RDC to support Widevine secure pipe */
int set_widevine_vpu_secure_mode(uint32_t cmd);

/* Configure RDC to support G2D secure pipe */
int set_widevine_g2d_secure_mode(uint32_t cmd);

int get_widevine_g2d_secure_mode(int &mode);

int get_ime_secure_mode(int &mode);

int set_dcss_secure(uint32_t cmd);

/* Configure xRDC for DCnano policy */
int set_dcnano_secure(uint32_t cmd);

int set_ime_secure(uint32_t cmd, handle_t chan);

/* Configre RDC memory orgion */
int set_rdc_mem_region();

#define RDC_MDAn(n) (rdc_base + 0x200 + (n * 4))
#define MRSAn(n)    (rdc_base + 0x800 + (n) * 0x10)
#define MREAn(n)    (rdc_base + 0x804 + (n) * 0x10)
#define MRCn(n)     (rdc_base + 0x808 + (n) * 0x10)
#define DID0 (0x0)
#define DID1 (0x1)
#define DID2 (0x2)
#define DID3 (0x3)

#define BIT(nr)   (1UL << (nr))
#define D3R  BIT(7)
#define D3W  BIT(6)
#define D2R  BIT(5)
#define D2W  BIT(4)
#define D1R  BIT(3)
#define D1W  BIT(2)
#define D0R  BIT(1)
#define D0W  BIT(0)

#define LCK  BIT(31)
#define ENA  BIT(30)

union rdc_setting {
        uint32_t rdc_mda; /* Master Domain Assignment */
        uint32_t rdc_pdap; /* Peripheral Domain Access Permissions */
        uint32_t rdc_mem_region[3]; /* Memory Region Access Control */
};
struct imx_rdc_cfg {
        int index;
        union rdc_setting setting;
};


#define RDC_MEM_REGIONn(i, msa, mea, mrc)       \
        { (i),                                  \
          .setting.rdc_mem_region[0] = (msa),   \
          .setting.rdc_mem_region[1] = (mea),   \
          .setting.rdc_mem_region[2] = (mrc),   \
        }

__END_CDECLS
