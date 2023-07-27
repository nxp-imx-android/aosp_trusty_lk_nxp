/*
 * Copyright 2023 NXP
 *
 */

#ifndef _IMX_AMPHION_H_
#define _IMX_AMPHION_H_

struct vpu_fastcall_message {
        uint32_t secure_memory_offset;
        uint32_t src_offset;
        uint32_t dst_offset;
        uint64_t size;
};

struct vpu_ctx {
        void*    message_buffer;
        uint64_t message_buffer_id;
        uint32_t message_buffer_size;
        uint64_t message_client_id;

        void*    hdr_buffer;
        uint64_t hdr_buffer_id;
        uint32_t hdr_buffer_size;
        uint64_t hdr_client_id;
};

#define SYSCALL_PLATFORM_FD_AMPHION 0x8
#define AMPHION_CLEAR_BOOT_BUFFER 0x00000001
#define AMPHION_GET_FIRMWARE_POWER 0x00000002

#endif

