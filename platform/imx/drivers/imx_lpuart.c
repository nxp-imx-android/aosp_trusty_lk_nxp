/*
 * Copyright NXP 2018
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

#include <debug.h>
#include <reg.h>
#include <dev/uart.h>
#include <imx-regs.h>

#define STAT_TDRE       (1 << 23)
#define READ32(addr)		(*REG32(addr))
#define WRITE32(val, addr)	(READ32(addr) = val)

#define REG_DATA 0x1c
#define REG_STAT 0x14

#define  UART_BASE	CONFIG_CONSOLE_TTY_VIRT

void uart_init(void)
{
	/*
	 * UART inited in ATF in imx8.
	 */
}

void uart_flush_tx(int port)
{
}

int uart_getc(int port, bool wait)
{
	return '\0';
}

int uart_putc(int port, char c )
{
	if (c == '\n')
		uart_putc(0, '\r');

	while (!(READ32(UART_BASE + REG_STAT) & STAT_TDRE))
		;
	WRITE32(c, (UART_BASE + REG_DATA));

	return 0;
}
