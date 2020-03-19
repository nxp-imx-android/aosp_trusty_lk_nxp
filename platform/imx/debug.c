/*
 * Copyright (c) 2017 Google Inc. All rights reserved
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
 */

#include <dev/uart.h>
#include <kernel/thread.h>
#include <platform/debug.h>
#include <lib/sm/smcall.h>
#include <lib/sm.h>
#include <lk/init.h>

#define SMC_ENTITY_CONSOLE 52
#define SMC_SC_SHARED_CONSOLE_CTL SMC_STDCALL_NR(SMC_ENTITY_CONSOLE, 0)
#define TRUSTY_CONSOLE_DISABLE 0
#define TRUSTY_CONSOLE_ENABLE 1
bool no_console = false;

static long console_stdcall(struct smc32_args* args) {
    if (args->smc_nr == SMC_SC_SHARED_CONSOLE_CTL) {
       if (args->params[1] == TRUSTY_CONSOLE_ENABLE) {
           no_console = false;
       }  else {
           no_console = true;
       }
    }
    return 0;
}

static struct smc32_entity console_entity = {
    .stdcall_handler = console_stdcall,
};

void console_smcall_init(uint level) {
    no_console = false;
    sm_register_entity(SMC_ENTITY_CONSOLE, &console_entity);
}
void platform_dputc(char c) {
    if (no_console)
        return;
    uart_putc(0, c);
}

int platform_dgetc(char* c, bool wait) {
    int res = -1;

    if (wait)
        thread_sleep(100);

    return res;
}
LK_INIT_HOOK(uart_console, console_smcall_init, LK_INIT_LEVEL_PLATFORM);
