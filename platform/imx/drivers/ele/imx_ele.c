// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <err.h>
#include <lk/compiler.h>
#include <lk/init.h>
#include <sys/types.h>
#include <platform.h>
#include <kernel/vm.h>
#include <kernel/mutex.h>
#include <arch/ops.h>
#include <uapi/trusty_uuid.h>
#include <lib/trusty/sys_fd.h>
#include <lib/trusty/trusty_app.h>
#include <platform/imx_ele.h>
#include <imx-regs.h>
#include "imx_mu.h"

#define DRIVER_FD SYSCALL_PLATFORM_FD_ELE
#define CHECK_FD(x) \
        do { if(x!=DRIVER_FD) return ERR_BAD_HANDLE; } while (0)

#define PRINT_TRUSTY_APP_UUID(tid, u)                                          \
    LTRACEF("trusty_app %d uuid: 0x%x 0x%x 0x%x 0x%x%x 0x%x%x%x%x%x%x\n", tid, \
            (u)->time_low, (u)->time_mid, (u)->time_hi_and_version,            \
            (u)->clock_seq_and_node[0], (u)->clock_seq_and_node[1],            \
            (u)->clock_seq_and_node[2], (u)->clock_seq_and_node[3],            \
            (u)->clock_seq_and_node[4], (u)->clock_seq_and_node[5],            \
            (u)->clock_seq_and_node[6], (u)->clock_seq_and_node[7]);

/* Definitions for communication protocol */
#define ELE_VERSION_BASELINE 0x06
#define ELE_VERSION_HSM	     0x07
#define ELE_COMMAND_SUCCEED 0x00
#define ELE_COMMAND_FAILED  0x29
#define ELE_REQUEST_TAG	    0x17
#define ELE_RESPONSE_TAG    0xe1

#define UID_SIZE (4 * sizeof(uint32_t))

/* Definitions for ELE API */
#define ELE_CMD_SESSION_OPEN  0x10
#define ELE_CMD_SESSION_CLOSE 0x11
#define ELE_CMD_SESSION_DEVICE_INFO 0x16
#define ELE_CMD_RNG_GET	  0xCD
#define ELE_CMD_TRNG_STATE	    0xA4
#define ELE_CMD_GET_INFO	    0xDA
#define ELE_CMD_DERIVE_KEY	    0xA9

#define ELE_MU_ID  0x2
#define ELE_MU_IRQ 0x0

#if defined(MACH_IMX8ULP)
#define ELE_MU_DID 0x7
#elif defined(MACH_IMX93)
#define ELE_MU_DID 0x3
#else
#error "ELE_MU_DID not specified for this platform"
#endif

#define CRC_TO_COMPUTE 0xdeadbeef

#define SIZE_MSG(_msg) size_msg(sizeof(_msg))
#define GENMASK_32(h, l) (((~(0U)) << (l)) & (~(0U) >> (32 - 1 - (h))))

static struct mutex lock = MUTEX_INITIAL_VALUE(lock);

struct get_info_msg_rsp {
	uint32_t rsp_code;
	uint16_t soc_id;
	uint16_t soc_rev;
	uint16_t lifecycle;
	uint16_t sssm_state;
	uint32_t uid[4];
	uint32_t sha256_rom_patch[8];
	uint32_t sha256_fw[8];
} __PACKED;

struct session_get_device_info_rsp {
	uint32_t rsp_code;
	uint32_t user_sab_id;
	uint32_t chip_uid[4];
	uint16_t chip_life_cycle;
	uint16_t chip_monotonic_counter;
	uint32_t ele_version;
	uint32_t ele_version_ext;
	uint8_t fips_mode;
	uint8_t reserved[3];
	uint32_t crc;
} __PACKED;

struct response_code {
	uint8_t status;
	uint8_t rating;
	uint16_t rating_extension;
} __PACKED;

static struct uuid hwcrypto_ta_uuid = {
    0x1adaf827,
    0x806b,
    0x4bcf,
    {0xbc, 0xec, 0x7e, 0x7d, 0x2f, 0x5a, 0x0a, 0x5c},
};

static vaddr_t imx_ele_va;
static bool ele_inited = false;

static bool check_uuid_equal(const struct uuid* a, const struct uuid* b) {
    return memcmp(a, b, sizeof(struct uuid)) == 0;
}

static bool timeout_elapsed(lk_time_ns_t timeout) {
	return current_time() > timeout;
}

static void print_rsp_code(const struct response_code rsp)
{
	printf("Response status 0x%" PRIx8 ", rating 0x%" PRIx8 " (ext 0x%" PRIx16
	     ")", rsp.status, rsp.rating, rsp.rating_extension);
}

static void print_msg_header(const struct imx_mu_msg_header hdr)
{
	printf("Header vers 0x%" PRIx8 ", size %" PRId8 ", tag 0x%" PRIx8
	     ", cmd 0x%" PRIx8,
	     hdr.version, hdr.size, hdr.tag, hdr.command);
}

static void dump_message(const struct imx_mu_msg *msg)
{
	size_t i = 0;
	size_t size = msg->header.size;
	uint32_t *data = (uint32_t *)msg;

	printf("Dump of message %p(%lu)\n", data, size);
	for (i = 0; i < size; i++)
		printf("word %lu: %d", i, data[i]);
}

static size_t size_msg(size_t cmd)
{
	size_t words = round_up(cmd, sizeof(uint32_t)) / sizeof(uint32_t);

	/* Add the header size */
	words = words + 1;

	return words;
}

/*
 * The CRC for the message is computed xor-ing all the words of the message:
 * the header and all the words except the word storing the crc
 *
 * msg: MU message to hash
 */
static uint32_t compute_crc(const struct imx_mu_msg *msg)
{
	uint32_t crc = 0;
	size_t i = 0;
	/* The CRC is included in the size */
	size_t size = msg->header.size - 1;
	uint32_t *payload = (uint32_t *)msg;

	for (i = 0; i < size; i++)
		crc ^= payload[i];

	return crc;
}

/*
 * The CRC is the last word of the message
 *
 * msg: MU message to hash
 */
static void update_crc(struct imx_mu_msg *msg)
{
	msg->data.u32[msg->header.size - 2] = compute_crc(msg);
}

static struct response_code get_response_code(uint32_t word)
{
	struct response_code rsp = {};

	rsp.rating_extension = (word & GENMASK_32(31, 16)) >> 16;
	rsp.rating = (word & GENMASK_32(15, 8)) >> 8;
	rsp.status = (word & GENMASK_32(7, 0)) >> 0;

	return rsp;
}

/*
 * Initiate a communication with the EdgeLock Enclave. It sends a message
 * and expects an answer.
 *
 * @msg: MU message
 */
static int imx_ele_call(struct imx_mu_msg *msg)
{
	int res = -1;
	struct response_code rsp = {};

	if (msg->header.tag != ELE_REQUEST_TAG) {
		printf("Request has invalid tag: %" PRIx8 " instead of %" PRIx32,
		     msg->header.tag, ELE_REQUEST_TAG);
		return -1;
	}

	res = imx_mu_call(imx_ele_va, msg, true);
	if (res) {
		printf("Failed to transmit message: %" PRIx32, res);
		print_msg_header(msg->header);
		dump_message(msg);
		return res;
	}

	rsp = get_response_code(msg->data.u32[0]);

	if (msg->header.tag != ELE_RESPONSE_TAG) {
		printf("Response has invalid tag: %" PRIx8 " instead of %" PRIx32,
		     msg->header.tag, ELE_RESPONSE_TAG);
		print_msg_header(msg->header);
		return -1;
	}

	if (rsp.status == ELE_COMMAND_FAILED) {
		printf("Command has failed");
		print_rsp_code(rsp);
		return -1;
	}

	/* The rating can be different in success and failing case */
	if (rsp.rating != 0) {
		printf("Command has invalid rating: %" PRIx8, rsp.rating);
		print_rsp_code(rsp);
		return -1;
	}

	return 0;
}

/*
 * EdgeLock Enclave and MU driver initialization.
 */
static int imx_ele_init(void)
{
	imx_mu_init(MU_BASE_VIRT);
	imx_ele_va = MU_BASE_VIRT;
	ele_inited = true;

	return 0;
}

/*
 * Get device information from EdgeLock Enclave
 *
 * @session_handle: EdgeLock Enclave session handler
 * @rsp: Device info
 */
static int
imx_ele_session_get_device_info(int32_t session_handle,
				struct session_get_device_info_rsp *rsp)
{
	int res = -1;

	struct session_get_device_info_cmd {
		uint32_t session_handle;
	} cmd = {
		.session_handle = session_handle,
	};

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_SESSION_DEVICE_INFO,
	};

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	res = imx_ele_call(&msg);
	if (res)
		return res;

	memcpy(rsp, msg.data.u32, sizeof(*rsp));

	if (compute_crc(&msg) != rsp->crc)
		return -1;

	return 0;
}

/*
 * Open a session with EdgeLock Enclave. It return a session handler.
 *
 * @session_handle: EdgeLock Enclave session handler
 */
static int imx_ele_session_open(uint32_t *session_handle)
{
	int res = -1;
	struct open_session_cmd {
		uint8_t mu_id;
		uint8_t interrupt_num;
		uint8_t tz;
		uint8_t did;
		uint8_t priority;
		uint8_t op_mode;
		uint16_t reserved;
	} __PACKED cmd = {
		.mu_id = ELE_MU_ID,
		.interrupt_num = ELE_MU_IRQ,
		.tz = 0,
		.did = ELE_MU_DID,
		.priority = 0,
		.op_mode = 0,
		.reserved = 0,
	};

	struct open_session_rsp {
		uint32_t rsp_code;
		uint32_t session_handle;
	} *rsp = NULL;

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_SESSION_OPEN,
	};

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	res = imx_ele_call(&msg);
	if (res)
		return res;

	rsp = (void *)msg.data.u32;

	if (session_handle)
		*session_handle = rsp->session_handle;

	return 0;
}

/*
 * Close a session with EdgeLock Enclave.
 *
 * @session_handle: EdgeLock Enclave session handler
 */
static int imx_ele_session_close(uint32_t session_handle)
{
	struct close_session_cmd {
		uint32_t session_handle;
	} cmd = {
		.session_handle = session_handle,
	};

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_SESSION_CLOSE,
	};

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	return imx_ele_call(&msg);
}

/*
 * Get random data from the EdgeLock Enclave
 *
 * @buffer: RNG data output
 * @size: RNG data size
 */
static int imx_ele_rng_get_random(paddr_t buffer, size_t size)
{
	struct rng_get_random_cmd {
		uint32_t out_addr_msb;
		uint32_t out_addr_lsb;
		uint32_t out_size;
	} cmd = {
		.out_addr_msb = 0,
		.out_addr_lsb = (uint64_t)buffer & GENMASK_32(31, 0),
		.out_size = (uint32_t)size,
	};

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_RNG_GET,
	};

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	return imx_ele_call(&msg);
}

#define IMX_ELE_TRNG_STATUS_READY 0x3

/* Get the current state of the ELE TRNG */
static int imx_ele_rng_get_trng_state(void)
{
	int res = -1;

	struct rng_get_trng_state_msg_rsp {
		uint32_t rsp_code;
		uint8_t trng_state;
		uint8_t csal_state;
	} __PACKED *rsp = NULL;

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_BASELINE,
		.header.size = 1,
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_TRNG_STATE,
	};

	res = imx_ele_call(&msg);
	if (res)
		printf("Failed to get TRNG current state");

	rsp = (void *)msg.data.u32;

	if (rsp->trng_state != IMX_ELE_TRNG_STATUS_READY)
		return -1;
	else
		return 0;
}

int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	int res = -1;
	uint32_t session_handle = 0;
	/*
	 * The die ID must be cached because some board configuration prevents
	 * the MU to be used by TEE at runtime.
	 */
	static struct session_get_device_info_rsp rsp = {};

	if (rsp.rsp_code)
		goto out;

	res = imx_ele_session_open(&session_handle);
	if (res)
		goto err;

	res = imx_ele_session_get_device_info(session_handle, &rsp);
	if (res)
		goto err;

	res = imx_ele_session_close(session_handle);
	if (res)
		goto err;

out:
	/*
	 * In the device info array return by the ELE, the words 2, 3, 4 and 5
	 * are the device UID.
	 */
	memcpy(buffer, rsp.chip_uid, MIN(UID_SIZE, len));

	return 0;
err:
	panic("Fail to get the device UID");
	return -1;
}

#if defined(MACH_IMX93)
static int tee_otp_get_hw_unique_key(user_addr_t hwkey, size_t key_size, user_addr_t ctx, size_t ctx_size)
{
	int res = -1;
	uint8_t *ctx_addr = NULL;
	uint8_t *key_addr = NULL;
	paddr_t key_paddr, ctx_paddr;

	// sanity check the key and context
	if (ctx_size >= (1U << 16) - 1) {
		printf("%s: Invalid context size!\n", __func__);
		return -1;
	}
	if ((key_size != 16) && (key_size != 32)) {
		printf("%s: Invalid key size!\n", __func__);
		return -1;
	}
	if (!hwkey || !ctx) {
		printf("%s: invalid input buffer!\n", __func__);
		return -1;
	}

	// alloc temp buffer for input context in case it's not cacheline aligned
	ctx_addr = memalign(64, ctx_size);
	if (!ctx_addr) {
		printf("%s: Fail to alloc memory!\n", __func__);
		return -1;
	}
	res = copy_from_user(ctx_addr, ctx, ctx_size);
        if (unlikely(res != 0)) {
            printf("%s: failed to copy data from user!\n", __func__ );
            return -1;
	}

	// key buffer
	key_addr = memalign(64, key_size);
	if (!key_addr) {
		printf("%s: Fail to alloc memory!\n", __func__);
		res = -1;
		goto exit;
	}

	ctx_paddr = vaddr_to_paddr(ctx_addr);
	key_paddr = vaddr_to_paddr(key_addr);
	arch_clean_cache_range((addr_t)(ctx_addr), ctx_size);
	arch_clean_cache_range((addr_t)(key_addr), key_size);

	struct key_derive_cmd {
		uint32_t key_addr_msb;
		uint32_t key_addr_lsb;
		uint32_t ctx_addr_msb;
		uint32_t ctx_addr_lsb;
		uint16_t key_size;
		uint16_t ctx_size;
		uint32_t crc;
	} __PACKED cmd = {
		.key_addr_msb = 0,
		.key_addr_lsb = key_paddr,
		.ctx_addr_msb = 0,
		.ctx_addr_lsb = ctx_paddr,
		.key_size = key_size,
		.ctx_size = ctx_size,
	};

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_BASELINE,
		.header.size = SIZE_MSG(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_DERIVE_KEY,
	};

	memcpy(msg.data.u8, &cmd, sizeof(cmd));
	update_crc(&msg);

	res = imx_ele_call(&msg);
	if (res) {
		printf("Failed to get the HUK!\n");
		res = -1;
		goto exit;
	}

	arch_clean_invalidate_cache_range((addr_t)(key_addr), key_size);

	res = copy_to_user(hwkey, key_addr, key_size);
        if (unlikely(res != 0)) {
            printf("%s: failed to copy data to user!\n", __func__ );
            res = -1;
            goto exit;
	}
	res = 0;

exit:
	if (ctx_addr)
		free(ctx_addr);
	if (key_addr)
		free(key_addr);

	return res;
}

static int generate_huk(user_addr_t user_ptr) {
	int ret;
	struct ele_huk_msg msg;

	ret = copy_from_user(&msg, user_ptr, sizeof(struct ele_huk_msg));
	if (unlikely(ret != 0)) {
            printf("%s: failed to copy data from user!\n", __func__ );
            return ret;
        }

	ret = tee_otp_get_hw_unique_key((user_addr_t)msg.hwkey, msg.key_size, (user_addr_t)msg.ctx, msg.ctx_size);

	return ret;
}
#endif /* MACH_IMX93 */

static void get_pseudo_random(uint8_t *buf, size_t len) {
	assert(buf);

	while (len) {
		/* lk's rand() returns 32 pseudo random bits */
		uint32_t val = (uint32_t) rand();
		size_t todo = len;
		for (size_t i = 0; i < sizeof(val) && i < todo; i++, len--) {
			*buf++ = val & 0xff;
			val >>= 8;
		}
	}
}

static int get_ele_random(uint8_t *buf, size_t len) {
	uint8_t *rand_buf = NULL;
	lk_time_ns_t timeout;
	int ret = 0;
	paddr_t ptr;

	if (!ele_inited) {
		printf("%s: ele is not inited!\n", __func__);
		ret = -1;
		goto exit;
	}
	rand_buf = memalign(64, len);
	if (!rand_buf) {
		printf("%s: failed to allocate memory len: %zu!\n", __func__, len);
		ret = -1;
		goto exit;
	}
	ptr = vaddr_to_paddr(rand_buf);
	arch_clean_cache_range((addr_t)(rand_buf), len);

	/*
	 * Check the current TRNG state of the ELE. The TRNG must be
	 * started with a command earlier in the boot to allow the TRNG
	 * to generate enough entropy.
	 * This command is only available starting imx8ulp A1.
	 */
	timeout = current_time() + 10;
	while (imx_ele_rng_get_trng_state() != 0)
		if (timeout_elapsed(timeout)) {
			printf("%s: ele timeout!\n", __func__);
			ret = -1;
			goto exit;
		}

	if (imx_ele_rng_get_random(ptr, len)) {
		printf("%s: get ele rng failed!\n", __func__);
		ret = -1;
		goto exit;
	}
	arch_clean_invalidate_cache_range((addr_t)(rand_buf), len);
	memcpy(buf, rand_buf, len);

exit:
	if (rand_buf)
		free(rand_buf);

	return ret;
}

void platform_random_get_bytes(uint8_t *buf, size_t len) {
	assert(buf);

	mutex_acquire(&lock);

        /* TODO "ENABLE_ELE_RANDOM" is not enabled due to the NS/S share the same MU
	 * to access ELE, so race may happen if we call ELE APIs at runtime. We should
	 * enable the "ENABLE_ELE_RANDOM" when we resolve the conflict.
	 */
#ifdef ENABLE_ELE_RANDOM
	if (get_ele_random(buf, len)) {
		// return pseudo random for any failure
		printf("%s: will return pseudo random!\n", __func__);
		get_pseudo_random(buf, len);
	}
#else
	get_pseudo_random(buf, len);
#endif
	mutex_release(&lock);

	return;
};

void init_imx_ele(uint level) {
        unsigned int randseed = 0;

	imx_ele_init();

#ifndef ENABLE_ELE_RANDOM
        /* seed the rand() with the PRNG from ELE */
	if (get_ele_random((uint8_t *)&randseed, sizeof(randseed)) == 0)
            srand(randseed);
#endif
}

LK_INIT_HOOK(imx_ele, init_imx_ele, LK_INIT_LEVEL_KERNEL - 1);

static int32_t sys_ele_ioctl(uint32_t fd, uint32_t cmd, user_addr_t user_ptr) {
	struct trusty_app* app = current_trusty_app();
	CHECK_FD(fd);
	switch (cmd) {
		case ELE_DERIVE_HUK:
			if (check_uuid_equal(&app->props.uuid, &hwcrypto_ta_uuid)) {
				return generate_huk(user_ptr);
			} else {
				printf("%s: unauthorized access!\n", __func__);
				return -1;
			}
		default:
			printf("%s: invalid ele syscall!\n", __func__);
			return -1;
	}
}
static const struct sys_fd_ops ele_ops = {
	.ioctl = sys_ele_ioctl,
};
void platform_init_ele(uint level) {
	install_sys_fd_handler(SYSCALL_PLATFORM_FD_ELE, &ele_ops);
}

LK_INIT_HOOK(ele_dev_init, platform_init_ele, LK_INIT_LEVEL_PLATFORM + 1);
