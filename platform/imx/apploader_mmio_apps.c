/*
 * Copyright (c) 2021, Google, Inc. All rights reserved
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Copyright 2021 NXP
 *
 */

#include <lib/trusty/trusty_app.h>
#include <lk/init.h>

#define DELETE_PAREN(args...) args
#define MMIO_APP(name, uuid) \
    TRUSTY_APP_MMIO_ALLOWED_RANGE(name, DELETE_PAREN uuid, 0xa4000000, 0x4c000000)

MMIO_APP(oemcrypto_range,
              ({0xdeb09cd6,
                0x7d65,
                0x4374,
                {0x8e, 0x3a, 0x63, 0x95, 0x5a, 0x27, 0x27, 0x9e}}));

static void add_app_ranges(uint level) {
    trusty_app_allow_mmio_range(&oemcrypto_range);
}

LK_INIT_HOOK(allowed_app_ranges,
             add_app_ranges,
             LK_INIT_LEVEL_APPS - 1);
