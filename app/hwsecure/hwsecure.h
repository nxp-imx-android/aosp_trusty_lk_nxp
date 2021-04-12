
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
int set_widevine_secure_mode(uint32_t cmd);

__END_CDECLS
