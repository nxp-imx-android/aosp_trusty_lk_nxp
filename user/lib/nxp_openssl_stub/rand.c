/*
 * Copyright 2023 NXP
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <uapi/err.h>

#include <lib/rng/trusty_rng.h>
#include <lib/rng/trusty_rng_internal.h>
#include <openssl/rand.h>
#include <platform/imx_rng.h>
#include <platform/imx_caam.h>
#include <platform/imx_ele.h>

#if defined(OPENSSL_IS_BORINGSSL)
/*
 * CRYPTO_sysrand is called by BoringSSL to obtain entropy from the OS on every
 * query for randomness. This needs to be fast, so we provide our own AES-CTR
 * PRNG seeded from hardware randomness, if available.
 */
void CRYPTO_sysrand(uint8_t* out, size_t requested) {
    if (trusty_rng_internal_system_rand(out, requested) != NO_ERROR) {
        abort();
    }
}

extern long _trusty_ioctl(uint32_t fd, uint32_t req, void *buf);
/*
 * seed the BoringSSL RNG from the hardware RNG with
 * "prediction resistance", this shall not fail.
 */
void CRYPTO_sysrand_for_seed(uint8_t* out, size_t requested) {
#ifdef WITH_CAAM_SUPPORT
    struct pr_rng_msg msg;

    msg.buf = out;
    msg.len = requested;
    if (_trusty_ioctl(SYSCALL_PLATFORM_FD_CAAM, CAAM_DERIVE_PR_RNG, &msg)) {
        printf("failed to generate the 'prediction resistance' random!\n");
        abort();
    }

#else
    /* fallback otherwise */
    if (trusty_rng_hw_rand(out, requested) != NO_ERROR) {
        abort();
    }
#endif
}
#endif /* OPENSSL_IS_BORINGSSL */
