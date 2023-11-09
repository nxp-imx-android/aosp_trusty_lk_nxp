/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright 2023 NXP
 */

#include <dev/interrupt/arm_gic.h>

#if WITH_SMP
struct arm_gic_affinities arch_cpu_num_to_gic_affinities(size_t cpu_num) {
    struct arm_gic_affinities out = {
        .aff0 = 0,
        .aff1 = (cpu_num & (0xff)),
        .aff2 = 0,
        .aff3 = 0,
    };

    return out;
}
#endif
