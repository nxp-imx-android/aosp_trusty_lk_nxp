/*
 * Copyright 2023 NXP
 *
 */

#ifndef __HWSECURE_SRV_H__
#define __HWSECURE_SRV_H__

struct hwservice_context {
    handle_t *chan;
};

int add_hwsecure_service(struct tipc_hset *hset, handle_t *chan);

#endif
