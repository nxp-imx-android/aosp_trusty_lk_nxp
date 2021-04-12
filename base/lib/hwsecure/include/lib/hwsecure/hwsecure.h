
#pragma once

#include <lk/compiler.h>
#include <stdint.h>

#include <interface/hwsecure/hwsecure.h>

__BEGIN_CDECLS

int set_lcdif_secure_access(int enable);
int set_widevine_secure_mode(int secure);


__END_CDECLS
