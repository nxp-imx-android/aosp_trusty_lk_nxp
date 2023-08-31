/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright 2023 NXP
 */

#ifndef __IMX_RNG_H__
#define __IMX_RNG_H__

#include <string.h>
#include <stdint.h>

/*
 * common structure for deriving hardware
 * random with "prediction resistance".
 */
struct pr_rng_msg {
    uint8_t *buf;
    size_t len;
};

#endif
