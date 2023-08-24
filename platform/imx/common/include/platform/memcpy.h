/*
 * Copyright 2023 NXP
 */

#ifndef _MEMCPY_H_
#define _MEMCPY_H_

extern void* __memcpy_aarch64(void *dst, const void *src, size_t size);

#define memcpy_aarch64 __memcpy_aarch64
#endif
