/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
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
#include <dev/uart.h>
#include <imx-regs.h>
#include <reg.h>

#define READ32(addr) (*REG32(addr))
#define WRITE32(val, addr) (READ32(addr) = val)

/* Register definitions */
#define URXD 0x0  /* Receiver Register */
#define UTXD 0x40 /* Transmitter Register */
#define UCR1 0x80 /* Control Register 1 */
#define UCR2 0x84 /* Control Register 2 */
#define UCR3 0x88 /* Control Register 3 */
#define UCR4 0x8c /* Control Register 4 */
#define UFCR 0x90 /* FIFO Control Register */
#define USR1 0x94 /* Status Register 1 */
#define USR2 0x98 /* Status Register 2 */
#define UESC 0x9c /* Escape Character Register */
#define UTIM 0xa0 /* Escape Timer Register */
#define UBIR 0xa4 /* BRM Incremental Register */
#define UBMR 0xa8 /* BRM Modulator Register */
#define UBRC 0xac /* Baud Rate Count Register */
#define UTS 0xb4  /* UART Test Register (mx31) */

/* UART Control Register Bit Fields.*/
#define URXD_CHARRDY (1 << 15)
#define URXD_ERR (1 << 14)
#define URXD_OVRRUN (1 << 13)
#define URXD_FRMERR (1 << 12)
#define URXD_BRK (1 << 11)
#define URXD_PRERR (1 << 10)
#define URXD_RX_DATA (0xFF)
#define UCR1_ADEN (1 << 15)     /* Auto dectect interrupt */
#define UCR1_ADBR (1 << 14)     /* Auto detect baud rate */
#define UCR1_TRDYEN (1 << 13)   /* Transmitter ready interrupt enable */
#define UCR1_IDEN (1 << 12)     /* Idle condition interrupt */
#define UCR1_RRDYEN (1 << 9)    /* Recv ready interrupt enable */
#define UCR1_RDMAEN (1 << 8)    /* Recv ready DMA enable */
#define UCR1_IREN (1 << 7)      /* Infrared interface enable */
#define UCR1_TXMPTYEN (1 << 6)  /* Transimitter empty interrupt enable */
#define UCR1_RTSDEN (1 << 5)    /* RTS delta interrupt enable */
#define UCR1_SNDBRK (1 << 4)    /* Send break */
#define UCR1_TDMAEN (1 << 3)    /* Transmitter ready DMA enable */
#define UCR1_UARTCLKEN (1 << 2) /* UART clock enabled */
#define UCR1_DOZE (1 << 1)      /* Doze */
#define UCR1_UARTEN (1 << 0)    /* UART enabled */

#define UTS_FRCPERR (1 << 13) /* Force parity error */
#define UTS_LOOP (1 << 12)    /* Loop tx and rx */
#define UTS_TXEMPTY (1 << 6)  /* TxFIFO empty */
#define UTS_RXEMPTY (1 << 5)  /* RxFIFO empty */
#define UTS_TXFULL (1 << 4)   /* TxFIFO full */
#define UTS_RXFULL (1 << 3)   /* RxFIFO full */
#define UTS_SOFTRST (1 << 0)  /* Software reset */
#define UART_BASE (SOC_REGS_VIRT + (CONFIG_CONSOLE_TTY_BASE - SOC_REGS_PHY))

void uart_init(void) {
    /*
     * Do nothing, debug uart share with normal world,
     * everything for uart intialization were done in bootloader.
     */
}

void uart_flush_tx(int port) {
    while (!(READ32(UART_BASE + UTS) & UTS_TXEMPTY))
        ;
}

int uart_getc(int port, bool wait) {
    if (wait)
        while (READ32(UART_BASE + UTS) & UTS_RXEMPTY)
            ;
    else if (!(READ32(UART_BASE + UTS) & UTS_RXEMPTY))
        return -1;

    return (READ32(UART_BASE + URXD) & URXD_RX_DATA);
}

int uart_putc(int port, char c) {
    if (c == '\n')
        uart_putc(0, '\r');

    WRITE32(c, UART_BASE + UTXD);

    /* wait until sent */
    while (!(READ32(UART_BASE + UTS) & UTS_TXEMPTY))
        ;

    return 0;
}
