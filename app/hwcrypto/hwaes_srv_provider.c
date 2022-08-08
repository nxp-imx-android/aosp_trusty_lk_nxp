/*
 * Copyright 2021 NXP
 */

#define TLOG_TAG "hwaes_srv"

#include <assert.h>
#include <lib/hwaes_server/hwaes_server.h>
#include <lib/hwkey/hwkey.h>
#include <lk/err_ptr.h>
#include <stdlib.h>
#include <string.h>
#include <trusty_log.h>
#include <uapi/err.h>

#include <openssl/evp.h>
#include <hwaes_srv_priv.h>
#include <hwkey_srv_priv.h>
#include <caam.h>

static uint32_t hwaes_check_arg_helper(size_t len, const uint8_t* data_ptr) {
    if (len == 0 || data_ptr == NULL) {
        return HWAES_ERR_INVALID_ARGS;
    }
    return HWAES_NO_ERROR;
}

static uint32_t hwaes_check_arg_in(const struct hwaes_arg_in* arg) {
    return hwaes_check_arg_helper(arg->len, arg->data_ptr);
}

static uint32_t hwaes_check_arg_out(const struct hwaes_arg_out* arg) {
    return hwaes_check_arg_helper(arg->len, arg->data_ptr);
}

uint32_t hwaes_aes_op(const struct hwaes_aes_op_args* args) {
    uint32_t rc;
    int ret;

    if (args->padding != HWAES_NO_PADDING) {
        TLOGE("the padding type is not implemented yet\n");
        return HWAES_ERR_NOT_IMPLEMENTED;
    }

    rc = hwaes_check_arg_in(&args->key);
    if (rc != HWAES_NO_ERROR) {
        TLOGE("key argument is missing\n");
        return rc;
    }

    rc = hwaes_check_arg_in(&args->text_in);
    if (rc != HWAES_NO_ERROR) {
        TLOGE("text_in argument is missing\n");
        return rc;
    }

    rc = hwaes_check_arg_out(&args->text_out);
    if (rc != HWAES_NO_ERROR) {
        TLOGE("text_out argument is missing\n");
        return rc;
    }

    /*
     * The current implementation does not support padding.
     * So the size of input buffer is the same as output buffer.
     */
    if (args->text_in.len != args->text_out.len) {
        TLOGE("text_in_len (%zd) is not equal to text_out_len (%zd)\n",
              args->text_in.len, args->text_out.len);
        return HWAES_ERR_INVALID_ARGS;
    }

    uint8_t key_buffer[AES_KEY_MAX_SIZE] = {0};
    struct hwaes_arg_in key = args->key;

    /* Fetch the real key contents if needed */
    if (args->key_type == HWAES_OPAQUE_HANDLE) {
        if (key.len > HWKEY_OPAQUE_HANDLE_MAX_SIZE) {
            TLOGE("Wrong opaque handle length: %zu\n", key.len);
            return HWAES_ERR_INVALID_ARGS;
        }
        if (key.data_ptr[key.len - 1] != 0) {
            TLOGE("Opaque handle is not null-terminated\n");
            return HWAES_ERR_INVALID_ARGS;
        }

        size_t key_len;
        hwaes_get_opaque_key((const char *)key.data_ptr, key_buffer, AES_KEY_MAX_SIZE, &key_len);

        key.data_ptr = key_buffer;
        key.len = key_len;
    }

    if (args->mode == HWAES_GCM_MODE) {
        if (hwaes_check_arg_in(&args->iv) != HWAES_NO_ERROR) {
            TLOGE("iv argument is missing\n");
            return HWAES_ERR_INVALID_ARGS;
        }
        if (args->encrypt) {
            if (hwaes_check_arg_in(&args->tag_in) == HWAES_NO_ERROR) {
                TLOGE("Input authentication tag set while encrypting in GCM mode.\n");
                return HWAES_ERR_INVALID_ARGS;
            }
            if (hwaes_check_arg_out(&args->tag_out) != HWAES_NO_ERROR) {
                TLOGE("Missing output authentication tag in GCM mode.\n");
                return HWAES_ERR_INVALID_ARGS;
            }
        } else {
            if (hwaes_check_arg_in(&args->tag_in) != HWAES_NO_ERROR) {
                TLOGE("Missing input authentication tag in GCM mode\n");
                return HWAES_ERR_INVALID_ARGS;
            }
            if (hwaes_check_arg_out(&args->tag_out) == HWAES_NO_ERROR) {
                TLOGE("Output authentication tag set while decrypting in GCM mode\n");
                return HWAES_ERR_INVALID_ARGS;
            }
        }
        ret = caam_aes_gcm(args->encrypt, args->iv.data_ptr, args->iv.len, key.data_ptr,
                           key.len, args->aad.data_ptr, args->aad.len, args->text_in.data_ptr,
                           args->text_in.len, args->text_out.data_ptr, args->text_out.len,
                           args->tag_in.data_ptr, args->tag_in.len, args->tag_out.data_ptr,
                           args->tag_out.len);
        if (ret) {
            TLOGE("AES GCM calculation failed.\n");
            return HWAES_ERR_GENERIC;
        }
    } else if (args->mode == HWAES_CBC_MODE) {
        if (hwaes_check_arg_in(&args->iv) != HWAES_NO_ERROR) {
            TLOGE("iv argument is missing\n");
            return HWAES_ERR_INVALID_ARGS;
        }
        if (hwaes_check_arg_in(&args->aad) == HWAES_NO_ERROR) {
            TLOGE("AAD is not supported in CBC mode!\n");
            return HWAES_ERR_INVALID_ARGS;
        }
        if (hwaes_check_arg_in(&args->tag_in) == HWAES_NO_ERROR) {
            TLOGE("Authentication tag_in is not supported in CBC mode!\n");
            return HWAES_ERR_INVALID_ARGS;
        }
        if (hwaes_check_arg_out(&args->tag_out) == HWAES_NO_ERROR) {
            TLOGE("Authentication tag_out is not supported in CBC mode!\n");
            return HWAES_ERR_INVALID_ARGS;
        }
        ret = caam_aes_cbc(args->encrypt, args->iv.data_ptr, args->iv.len, key.data_ptr,
                           key.len, args->text_in.data_ptr, args->text_in.len,
                           args->text_out.data_ptr, args->text_out.len);
        if (ret) {
            TLOGE("AES CBC calculation failed.\n");
            return HWAES_ERR_GENERIC;
        }
    } else if (args->mode == HWAES_ECB_MODE){
        if (hwaes_check_arg_in(&args->iv) != HWAES_NO_ERROR) {
            TLOGE("iv argument is missing\n");
            return HWAES_ERR_INVALID_ARGS;
        }
        ret = caam_aes_ecb(args->encrypt, key.data_ptr, key.len, args->text_in.data_ptr,
                           args->text_in.len, args->text_out.data_ptr, args->text_out.len);
        if (ret) {
            TLOGE("AES ECB calculation failed.\n");
            return HWAES_ERR_GENERIC;
        }
    } else if (args->mode == HWAES_CTR_MODE){
        if (hwaes_check_arg_in(&args->iv) != HWAES_NO_ERROR) {
            TLOGE("iv argument is missing\n");
            return HWAES_ERR_INVALID_ARGS;
        }
        ret = caam_aes_ctr(args->encrypt, args->iv.data_ptr, args->iv.len, key.data_ptr,
                           key.len, args->text_in.data_ptr, args->text_in.len,
                           args->text_out.data_ptr, args->text_out.len);
        if (ret) {
            TLOGE("AES CTR calculation failed.\n");
            return HWAES_ERR_GENERIC;
        }
    } else {
        TLOGE("AES mode %d is not implemented yet\n", args->mode);
        return HWAES_ERR_NOT_IMPLEMENTED;
    }

    return HWAES_NO_ERROR;
}

void hwaes_init_srv_provider(void) {
    int rc;

    TLOGD("Init HWAES service provider\n");
    /* Nothing to initialize here, just start service */
    rc = hwaes_start_service();
    if (rc != NO_ERROR) {
        TLOGE("failed (%d) to start HWAES service\n", rc);
    }
}
