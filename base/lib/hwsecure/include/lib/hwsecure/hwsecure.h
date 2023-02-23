/*
 * Copyright 2023 NXP
 *
 */

#pragma once

#include <lk/compiler.h>
#include <stdint.h>

#include <interface/hwsecure/hwsecure.h>

__BEGIN_CDECLS

int set_dcnano_secure_access(int enable);
int set_lcdif_secure_access(int enable);
int set_widevine_g2d_secure_mode(int secure);
int get_widevine_g2d_secure_mode(int* secure_mode);
int set_dcss_secure_access(int enable);
int set_rdc_mem_region(void);
int set_ime_secure_access(int enable);
int get_ime_secure_mode(int* secure_mode);

__END_CDECLS
