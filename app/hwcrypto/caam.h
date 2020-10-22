/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2017 NXP
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _CAAM_H
#define _CAAM_H

#include <stdbool.h>
#include <stdint.h>
#include <nxp_hwcrypto_consts.h>
#include "hwkey_keyslots.h"

enum hash_algo {
    SHA1 = 0,
    SHA256
};

struct caam_job {
    uint32_t dsc[MAX_DSC_NUM]; /* job descriptors */
    uint32_t dsc_used;         /* number of filled entries */
    uint32_t status;           /* job result */
};

struct caam_job_rings {
    uint32_t in[1];  /* single entry input ring */
    uint32_t out[2]; /* single entry output ring (consists of two words) */
};

/* One entry in the Scatter/Gather Table */
typedef struct _caam_sgt_entry
{
    /* 64-bit address. */
    uint32_t address_h;
    uint32_t address_l;
    uint32_t length;
    uint32_t offset;
} caam_sgt_entry_t;

/* Definitions SGT entry type */
typedef enum _caam_sgt_entry_type
{
    caam_sgt_entry_not_last = 0, /* Do not set the Final Bit in SGT entries */
    caam_sgt_entry_last = 1,    /* Sets Final Bit in the last SGT entry */
} caam_sgt_entry_type_t;

int init_caam_env(void);

void caam_test(void);

void caam_open(void);

uint32_t caam_gen_blob(const uint8_t* kmod,
                       size_t kmod_size,
                       const uint8_t* plain_text,
                       uint8_t* blob,
                       uint32_t size);

uint32_t caam_decap_blob(const uint8_t* kmod,
                         size_t kmod_size,
                         uint8_t* plain_text,
                         const uint8_t* blob,
                         uint32_t size);

uint32_t caam_aes_op(const uint8_t* key,
                     size_t key_size,
                     const uint8_t* input,
                     uint8_t* output,
                     size_t len,
                     bool enc);

uint32_t caam_hwrng(uint8_t* output_ptr, uint32_t output_len);

uint32_t caam_gen_kdfv1_root_key(uint8_t* out, uint32_t size);

void caam_get_keybox(struct keyslot_package *kbox);

uint32_t caam_hash_pa(uint32_t in, uint32_t out,
                      uint32_t len, enum hash_algo algo);

uint32_t caam_gen_blob_pa(uint32_t kmod_pa,
                          size_t kmod_size,
                          uint32_t plain_pa,
                          uint32_t blob_pa,
                          uint32_t size);

uint32_t caam_hwrng_pa(uint32_t buf_pa, uint32_t len);

uint32_t caam_gen_bkek_key(const uint8_t* kmod, uint32_t kmod_size,
                           uint32_t out, uint32_t size);
uint32_t caam_gen_bkek_key_pa(uint32_t kmod, uint32_t out, uint32_t size);

uint32_t caam_gen_mppubk(uint32_t out);
uint32_t caam_gen_mppubk_pa(uint32_t out);
uint32_t caam_gen_mppriv(void);
/* CAAM AES GCM mode - virtual address*/
int caam_aes_gcm(uint32_t enc_flag,
                      const void * iv,
                      size_t iv_size,
                      const void * key,
                      size_t key_size,
                      const void * aad,
                      size_t aad_len,
                      const void * input_text,
                      size_t input_text_size,
                      void * output_text,
                      size_t output_text_size,
                      const void * tag_in,
                      size_t tag_in_size,
                      void * tag_out,
                      size_t tag_out_size);
/* CAAM AES CBC mode - virtual address*/
int caam_aes_cbc(uint32_t enc_flag,
                      const void *iv,
                      size_t iv_size,
                      const void *key,
                      size_t key_size,
                      const void *input_text,
                      size_t input_text_size,
                      void *output_text,
                      size_t output_text_size);
/* CAAM AES ECB mode - virtual address*/
int caam_aes_ecb(uint32_t enc_flag,
                      const void * key,
                      size_t key_size,
                      const void * input_text,
                      size_t input_text_size,
                      void * output_text,
                      size_t output_text_size);
/* CAAM AES CTR mode - virtual address*/
int caam_aes_ctr(uint32_t enc_flag,
                      const void *iv,
                      size_t iv_size,
                      const void *key,
                      size_t key_size,
                      const void *input_text,
                      size_t input_text_size,
                      void *output_text,
                      size_t output_text_size);
/* CAAM DES EDE ECB mode - virtual address*/
int caam_tdes_ecb(uint32_t enc_flag,
                      const void * key,
                      size_t key_size,
                      const void * input_text,
                      size_t input_text_size,
                      void * output_text,
                      size_t output_text_size);
/* DES EDE CBC mode*/
int caam_tdes_cbc(uint32_t enc_flag,
                  const void *iv,
                  size_t iv_size,
                  const void *key,
                  size_t key_size,
                  const void *input_text,
                  size_t input_text_size,
                  void *output_text,
                  size_t output_text_size);

/* Declare small scatter gather safe buffer (size must be power of 2) */
#define DECLARE_SG_SAFE_BUF(nm, sz) uint8_t nm[sz] __attribute__((aligned(sz)))

#endif
