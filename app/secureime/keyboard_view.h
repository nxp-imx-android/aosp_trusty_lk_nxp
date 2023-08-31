/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright 2023 NXP
 */

#pragma once

#include <vector>
#include <array>
#include <string>

#include <inttypes.h>
#include <layouts/layout.h>
#include <teeui/error.h>
#include <teeui/utils.h>

using namespace std;

#define BUTTON_DELETE 10
#define BUTTON_CANCEL 11

class keyboardView {
public:
	keyboardView(uint8_t *buffer, uint32_t length, uint32_t width, uint32_t height);
	~keyboardView() { buffer_ = nullptr; };

	int drawKeyboard();
	int getKeyboardText(uint32_t x, uint32_t y);

private:
	uint8_t *buffer_ = nullptr;
	uint32_t length_ = 0;
	uint32_t width_ = 0;
	uint32_t height_ = 0;
	std::vector<string> keyboard_layout = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"};
	teeui::layout_t<teeui::SecureIMELayout> layout_;

	int renderAndSwap();
};
