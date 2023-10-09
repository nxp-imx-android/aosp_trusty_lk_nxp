/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright 2023 NXP
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <uapi/err.h>

#include <lib/rng/trusty_rng.h>
#include <openssl/rand.h>
#include <platform/imx_rng.h>
#include <platform/imx_caam.h>
#include <platform/imx_ele.h>

#if defined(OPENSSL_IS_BORINGSSL)
extern long _trusty_ioctl(uint32_t fd, uint32_t req, void *buf);
/*
 * seed the BoringSSL RNG from the hardware RNG with
 * "prediction resistance", this shall not fail.
 */
void CRYPTO_sysrand_with_pr(uint8_t* out, size_t requested) {
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
