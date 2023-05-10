/*
 * Copyright 2023 NXP
 *
 */

#ifndef __IMX_ELE_H_
#define __IMX_ELE_H_

#define SYSCALL_PLATFORM_FD_ELE 0x8

struct ele_huk_msg {
	uint8_t *hwkey;
	uint8_t *ctx;
	size_t key_size;
	size_t ctx_size;
};

#define ELE_DERIVE_HUK 0x00000001

#endif // __IMX_ELE_H_
