/*
 * Copyright 2023 NXP
 */

#ifndef __ELE_H__
#define __ELE_H__

int generate_ele_rpmb_key(uint8_t *kbuf, size_t* klen);
int get_ele_huk(void);
int get_ele_derived_key(uint8_t *key, size_t key_size, uint8_t *ctx, size_t ctx_size);

#endif //__ELE_H__
