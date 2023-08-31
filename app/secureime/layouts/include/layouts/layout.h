/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright 2023 NXP
 *
 */

#pragma once

#include <teeui/button.h>
#include <teeui/label.h>
#include <teeui/utils.h>

#include "fonts.h"

namespace teeui {
DECLARE_PARAMETER(ButtonWidth);
DECLARE_PARAMETER(ButtonHeight);
DECLARE_PARAMETER(ButtonXGap);
DECLARE_PARAMETER(ButtonYGap);
DECLARE_PARAMETER(MarginLeft);
NEW_PARAMETER_SET(SecureIMEParameters,
			ButtonWidth,
			ButtonHeight,
			ButtonXGap,
			ButtonYGap,
			MarginLeft);

CONSTANT(ButtonFontSize, 72_px);
CONSTANT(ButtonFontTextSize, 60_px);
CONSTANT(ButtonColorDefault, 0xff1a73e8);

DECLARE_FONT_BUFFER(RobotoMedium, RobotoMedium, RobotoMedium_length);

CONSTANT(Button1PosX, MarginLeft());
CONSTANT(Button1PosY, ButtonYGap());

BEGIN_ELEMENT(Button1, teeui::Button, ConvexObjectCount(1))
Dimension(ButtonWidth(), ButtonHeight());
Position(Button1PosX, Button1PosY);
CornerRadius(10_dp);
ButtonColor(ButtonColorDefault);
RoundTopLeft;
RoundTopRight;
RoundBottomLeft;
RoundBottomRight;
END_ELEMENT();

BEGIN_ELEMENT(Button1_Text, teeui::Label)
Font(FONT(RobotoMedium));
FontSize(ButtonFontSize);
LineHeight(ButtonFontSize);
NumberOfLines(1);
Dimension(ButtonWidth(), ButtonHeight());
Position(Button1PosX, Button1PosY);
DefaultText("1");
HorizontalTextAlignment(Alignment::CENTER);
VerticalTextAlignment(Alignment::CENTER);
END_ELEMENT();


CONSTANT(Button2PosX, Button1PosX + ButtonWidth() + ButtonXGap());
CONSTANT(Button2PosY, Button1PosY);

BEGIN_ELEMENT(Button2, teeui::Button, ConvexObjectCount(1))
Dimension(ButtonWidth(), ButtonHeight());
Position(Button2PosX, Button2PosY);
CornerRadius(10_dp);
ButtonColor(ButtonColorDefault);
RoundTopLeft;
RoundTopRight;
RoundBottomLeft;
RoundBottomRight;
END_ELEMENT();

BEGIN_ELEMENT(Button2_Text, teeui::Label)
Font(FONT(RobotoMedium));
FontSize(ButtonFontSize);
LineHeight(ButtonFontSize);
NumberOfLines(1);
Dimension(ButtonWidth(), ButtonHeight());
Position(Button2PosX, Button2PosY);
DefaultText("2");
HorizontalTextAlignment(Alignment::CENTER);
VerticalTextAlignment(Alignment::CENTER);
END_ELEMENT();

CONSTANT(Button3PosX, Button1PosX + ButtonWidth() * 2 + ButtonXGap() * 2);
CONSTANT(Button3PosY, Button1PosY);

BEGIN_ELEMENT(Button3, teeui::Button, ConvexObjectCount(1))
Dimension(ButtonWidth(), ButtonHeight());
Position(Button3PosX, Button3PosY);
CornerRadius(10_dp);
ButtonColor(ButtonColorDefault);
RoundTopLeft;
RoundTopRight;
RoundBottomLeft;
RoundBottomRight;
END_ELEMENT();

BEGIN_ELEMENT(Button3_Text, teeui::Label)
Font(FONT(RobotoMedium));
FontSize(ButtonFontSize);
LineHeight(ButtonFontSize);
NumberOfLines(1);
Dimension(ButtonWidth(), ButtonHeight());
Position(Button3PosX, Button3PosY);
DefaultText("3");
HorizontalTextAlignment(Alignment::CENTER);
VerticalTextAlignment(Alignment::CENTER);
END_ELEMENT();

CONSTANT(Button4PosX, Button1PosX);
CONSTANT(Button4PosY, Button1PosY + ButtonHeight() + ButtonYGap());

BEGIN_ELEMENT(Button4, teeui::Button, ConvexObjectCount(1))
Dimension(ButtonWidth(), ButtonHeight());
Position(Button4PosX, Button4PosY);
CornerRadius(10_dp);
ButtonColor(ButtonColorDefault);
RoundTopLeft;
RoundTopRight;
RoundBottomLeft;
RoundBottomRight;
END_ELEMENT();

BEGIN_ELEMENT(Button4_Text, teeui::Label)
Font(FONT(RobotoMedium));
FontSize(ButtonFontSize);
LineHeight(ButtonFontSize);
NumberOfLines(1);
Dimension(ButtonWidth(), ButtonHeight());
Position(Button4PosX, Button4PosY);
DefaultText("4");
HorizontalTextAlignment(Alignment::CENTER);
VerticalTextAlignment(Alignment::CENTER);
END_ELEMENT();

CONSTANT(Button5PosX, Button1PosX + ButtonWidth() + ButtonXGap());
CONSTANT(Button5PosY, Button1PosY + ButtonHeight() + ButtonYGap());

BEGIN_ELEMENT(Button5, teeui::Button, ConvexObjectCount(1))
Dimension(ButtonWidth(), ButtonHeight());
Position(Button5PosX, Button5PosY);
CornerRadius(10_dp);
ButtonColor(ButtonColorDefault);
RoundTopLeft;
RoundTopRight;
RoundBottomLeft;
RoundBottomRight;
END_ELEMENT();

BEGIN_ELEMENT(Button5_Text, teeui::Label)
Font(FONT(RobotoMedium));
FontSize(ButtonFontSize);
LineHeight(ButtonFontSize);
NumberOfLines(1);
Dimension(ButtonWidth(), ButtonHeight());
Position(Button5PosX, Button5PosY);
DefaultText("5");
HorizontalTextAlignment(Alignment::CENTER);
VerticalTextAlignment(Alignment::CENTER);
END_ELEMENT();

CONSTANT(Button6PosX, Button1PosX + ButtonXGap() * 2 + ButtonWidth() * 2);
CONSTANT(Button6PosY, Button1PosY + ButtonHeight() + ButtonYGap());

BEGIN_ELEMENT(Button6, teeui::Button, ConvexObjectCount(1))
Dimension(ButtonWidth(), ButtonHeight());
Position(Button6PosX, Button6PosY);
CornerRadius(10_dp);
ButtonColor(ButtonColorDefault);
RoundTopLeft;
RoundTopRight;
RoundBottomLeft;
RoundBottomRight;
END_ELEMENT();

BEGIN_ELEMENT(Button6_Text, teeui::Label)
Font(FONT(RobotoMedium));
FontSize(ButtonFontSize);
LineHeight(ButtonFontSize);
NumberOfLines(1);
Dimension(ButtonWidth(), ButtonHeight());
Position(Button6PosX, Button6PosY);
DefaultText("6");
HorizontalTextAlignment(Alignment::CENTER);
VerticalTextAlignment(Alignment::CENTER);
END_ELEMENT();

CONSTANT(Button7PosX, Button1PosX);
CONSTANT(Button7PosY, Button1PosY + ButtonHeight() * 2 + ButtonYGap() * 2);

BEGIN_ELEMENT(Button7, teeui::Button, ConvexObjectCount(1))
Dimension(ButtonWidth(), ButtonHeight());
Position(Button7PosX, Button7PosY);
CornerRadius(10_dp);
ButtonColor(ButtonColorDefault);
RoundTopLeft;
RoundTopRight;
RoundBottomLeft;
RoundBottomRight;
END_ELEMENT();

BEGIN_ELEMENT(Button7_Text, teeui::Label)
Font(FONT(RobotoMedium));
FontSize(ButtonFontSize);
LineHeight(ButtonFontSize);
NumberOfLines(1);
Dimension(ButtonWidth(), ButtonHeight());
Position(Button7PosX, Button7PosY);
DefaultText("7");
HorizontalTextAlignment(Alignment::CENTER);
VerticalTextAlignment(Alignment::CENTER);
END_ELEMENT();

CONSTANT(Button8PosX, Button1PosX + ButtonXGap() + ButtonWidth());
CONSTANT(Button8PosY, Button1PosY + ButtonHeight() * 2 + ButtonYGap() * 2);

BEGIN_ELEMENT(Button8, teeui::Button, ConvexObjectCount(1))
Dimension(ButtonWidth(), ButtonHeight());
Position(Button8PosX, Button8PosY);
CornerRadius(10_dp);
ButtonColor(ButtonColorDefault);
RoundTopLeft;
RoundTopRight;
RoundBottomLeft;
RoundBottomRight;
END_ELEMENT();

BEGIN_ELEMENT(Button8_Text, teeui::Label)
Font(FONT(RobotoMedium));
FontSize(ButtonFontSize);
LineHeight(ButtonFontSize);
NumberOfLines(1);
Dimension(ButtonWidth(), ButtonHeight());
Position(Button8PosX, Button8PosY);
DefaultText("8");
HorizontalTextAlignment(Alignment::CENTER);
VerticalTextAlignment(Alignment::CENTER);
END_ELEMENT();

CONSTANT(Button9PosX, Button1PosX + ButtonXGap() * 2 + ButtonWidth() * 2);
CONSTANT(Button9PosY, Button1PosY + ButtonHeight() * 2 + ButtonYGap() * 2);

BEGIN_ELEMENT(Button9, teeui::Button, ConvexObjectCount(1))
Dimension(ButtonWidth(), ButtonHeight());
Position(Button9PosX, Button9PosY);
CornerRadius(10_dp);
ButtonColor(ButtonColorDefault);
RoundTopLeft;
RoundTopRight;
RoundBottomLeft;
RoundBottomRight;
END_ELEMENT();

BEGIN_ELEMENT(Button9_Text, teeui::Label)
Font(FONT(RobotoMedium));
FontSize(ButtonFontSize);
LineHeight(ButtonFontSize);
NumberOfLines(1);
Dimension(ButtonWidth(), ButtonHeight());
Position(Button9PosX, Button9PosY);
DefaultText("9");
HorizontalTextAlignment(Alignment::CENTER);
VerticalTextAlignment(Alignment::CENTER);
END_ELEMENT();

CONSTANT(Button0PosX, Button1PosX + ButtonXGap() + ButtonWidth());
CONSTANT(Button0PosY, Button1PosY + ButtonHeight() * 3 + ButtonYGap() * 3);

BEGIN_ELEMENT(Button0, teeui::Button, ConvexObjectCount(1))
Dimension(ButtonWidth(), ButtonHeight());
Position(Button0PosX, Button0PosY);
CornerRadius(10_dp);
ButtonColor(ButtonColorDefault);
RoundTopLeft;
RoundTopRight;
RoundBottomLeft;
RoundBottomRight;
END_ELEMENT();

BEGIN_ELEMENT(Button0_Text, teeui::Label)
Font(FONT(RobotoMedium));
FontSize(ButtonFontSize);
LineHeight(ButtonFontSize);
NumberOfLines(1);
Dimension(ButtonWidth(), ButtonHeight());
Position(Button0PosX, Button0PosY);
DefaultText("0");
HorizontalTextAlignment(Alignment::CENTER);
VerticalTextAlignment(Alignment::CENTER);
END_ELEMENT();

CONSTANT(ButtonDeletePosX, Button1PosX);
CONSTANT(ButtonDeletePosY, Button1PosY + ButtonHeight() * 3 + ButtonYGap() * 3);

BEGIN_ELEMENT(ButtonDelete, teeui::Button, ConvexObjectCount(1))
Dimension(ButtonWidth(), ButtonHeight());
Position(ButtonDeletePosX, ButtonDeletePosY);
CornerRadius(10_dp);
ButtonColor(ButtonColorDefault);
RoundTopLeft;
RoundTopRight;
RoundBottomLeft;
RoundBottomRight;
END_ELEMENT();

BEGIN_ELEMENT(ButtonDelete_Text, teeui::Label)
Font(FONT(RobotoMedium));
FontSize(ButtonFontTextSize);
LineHeight(ButtonFontSize);
NumberOfLines(1);
Dimension(ButtonWidth(), ButtonHeight());
Position(ButtonDeletePosX, ButtonDeletePosY);
DefaultText("Delete");
HorizontalTextAlignment(Alignment::CENTER);
VerticalTextAlignment(Alignment::CENTER);
END_ELEMENT();

CONSTANT(ButtonEnterPosX, Button1PosX + ButtonWidth() * 2 + ButtonXGap() * 2);
CONSTANT(ButtonEnterPosY, Button1PosY + ButtonHeight() * 3 + ButtonYGap() * 3);

BEGIN_ELEMENT(ButtonEnter, teeui::Button, ConvexObjectCount(1))
Dimension(ButtonWidth(), ButtonHeight());
Position(ButtonEnterPosX, ButtonEnterPosY);
CornerRadius(10_dp);
ButtonColor(ButtonColorDefault);
RoundTopLeft;
RoundTopRight;
RoundBottomLeft;
RoundBottomRight;
END_ELEMENT();

BEGIN_ELEMENT(ButtonEnter_Text, teeui::Label)
Font(FONT(RobotoMedium));
FontSize(ButtonFontTextSize);
LineHeight(ButtonFontSize);
NumberOfLines(1);
Dimension(ButtonWidth(), ButtonHeight());
Position(ButtonEnterPosX, ButtonEnterPosY);
DefaultText("Enter");
HorizontalTextAlignment(Alignment::CENTER);
VerticalTextAlignment(Alignment::CENTER);
END_ELEMENT();

NEW_LAYOUT(SecureIMELayout,
		Button1,
		Button2,
		Button3,
		Button4,
		Button5,
		Button6,
		Button7,
		Button8,
		Button9,
		Button0,
		ButtonDelete,
		ButtonEnter,
		Button1_Text,
		Button2_Text,
		Button3_Text,
		Button4_Text,
		Button5_Text,
		Button6_Text,
		Button7_Text,
		Button8_Text,
		Button9_Text,
		Button0_Text,
		ButtonDelete_Text,
		ButtonEnter_Text);
}
