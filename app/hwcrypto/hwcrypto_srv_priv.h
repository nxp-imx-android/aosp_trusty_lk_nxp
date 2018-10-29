/*
 * Copyright (C) 2016-2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright 2018 NXP
 */
#pragma once

#include <lk/compiler.h>
#include "caam.h"

__BEGIN_CDECLS

void hwcrypto_init_srv_provider(void);
int hwcrypto_start_service(void);
int calculate_hash(uint32_t in_paddr, uint32_t in_len,
                   uint32_t out_paddr, enum hash_algo algo);

__END_CDECLS
