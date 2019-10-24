/*
 * Copyright (C) 2017 The Android Open Source Project
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
 */

#pragma once

#include <stdio.h>

#define TLOG_LVL_NONE 0
#define TLOG_LVL_ERROR 1
#define TLOG_LVL_INFO 2
#define TLOG_LVL_DEBUG 3

#ifndef TLOG_LVL
#define TLOG_LVL TLOG_LVL_DEFAULT
#endif

#if TLOG_LVL >= TLOG_LVL_DEBUG
#define TLOGD(fmt, ...) \
    fprintf(stderr, "%s: %d: " fmt, TLOG_TAG, __LINE__, ##__VA_ARGS__)
#else
#define TLOGD(fmt, ...)
#endif

#if TLOG_LVL >= TLOG_LVL_INFO
#define TLOGI(fmt, ...) \
    fprintf(stderr, "%s: " fmt, TLOG_TAG, ##__VA_ARGS__)
#else
#define TLOGI(fmt, ...)
#endif

#if TLOG_LVL >= TLOG_LVL_ERROR
#define TLOGE(fmt, ...) \
    fprintf(stderr, "%s: %d: " fmt, TLOG_TAG, __LINE__, ##__VA_ARGS__)
#else
#define TLOGE(fmt, ...)
#endif
