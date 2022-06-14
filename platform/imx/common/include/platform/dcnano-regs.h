/*
 * Copyright 2019 - 2021 NXP
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
 *
 */

#ifndef __LCDIF_REGS_H
#define __LCDIF_REGS_H

#define DCNANO_BASE_VIRT 0xFFFFFFFF2E050000

#define DCNANO_FRAMEBUFFERCONFIG        0x1240
#define DCNANO_FRAMEBUFFERADDRESS       0x1260
#define DCNANO_FRAMEBUFFERSTRIDE        0x1280
#define DCNANO_DISPLAYDITHERCONFIG      0x1360
#define DCNANO_DISPLAYDITHERTABLELOW    0x1380
#define DCNANO_DISPLAYDITHERTABLEHIGH   0x13a0
#define DCNANO_PANELCONFIG              0x13c0
#define DCNANO_PANELTIMING              0x13e0
#define DCNANO_HDISPLAY                 0x1400
#define DCNANO_HSYNC                    0x1420
#define DCNANO_VDISPLAY                 0x1480
#define DCNANO_VSYNC                    0x14a0
#define DCNANO_DISPLAYCURRENTLOCATION   0x14c0
#define DCNANO_GAMMAINDEX               0x14e0
#define DCNANO_GAMMADATA                0x1500
#define DCNANO_CURSORCONFIG             0x1520
#define DCNANO_CURSORADDRESS            0x1530
#define DCNANO_CURSORLOCATION           0x1540
#define DCNANO_CURSORBACKGROUND         0x1550
#define DCNANO_CURSORFOREGROUND         0x1560
#define DCNANO_DISPLAYINTR              0x1600
#define DCNANO_DISPLAYINTRENABLE        0x1610
#define DCNANO_DBICONFIG                0x1620
#define DCNANO_DBIIFRESET               0x1640
#define DCNANO_DBIWRCHAR1               0x1660
#define DCNANO_DBIWRCHAR2               0x1680
#define DCNANO_DBICMD                   0x16a0
#define DCNANO_DPICONFIG                0x16c0
#define DCNANO_DCCHIPREV                0x16f0
#define DCNANO_DCCHIPDATE               0x1700
#define DCNANO_DCCHIPPATCHREV           0x1720
#define DCNANO_DCTILEINCFG              0x1740
#define DCNANO_DCTILEUVFRAMEBUFFERADR   0x1760
#define DCNANO_DCTILEUVFRAMEBUFFERSTR   0x1780
#define DCNANO_DCPRODUCTID              0x17b0
#define DCNANO_DCSTATUS                 0x1800
#define DCNANO_DEBUGCOUNTERSELECT       0x1820
#define DCNANO_DEBUGCOUNTERVALUE        0x1840

#endif
