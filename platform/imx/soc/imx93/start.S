/*
 * Copyright 2023 NXP
 *
 */
#include <asm.h>

tmp        .req x9

// The cpuid of A55 core is in the affinity 1 of mpidr_el1,
// this funtion overrides the weak implemetation.
FUNCTION(arm64_curr_cpu_num)
mrs     x0, mpidr_el1
mov     tmp, #(0xff)
and     x0, tmp, x0, LSR #(8)
cmp     x0, #(1 << SMP_CPU_CLUSTER_SHIFT)
bge     .Lunsupported_cpu_num
ret

.Lunsupported_cpu_num:
mov     x0, #SMP_MAX_CPUS
ret
