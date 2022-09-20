/* Copyright 2022 NXP
 */

#include <algorithm>
#include <random>
#include <trusty_log.h>
#include <lib/rng/trusty_rng.h>
#include "keyboard_view.h"
#include "layouts/layout.h"

#define TLOG_TAG "secureime"

using namespace teeui;

#define line_stride  (4 * 720)
#define pixel_stride (4)

#define BUTTON_WIDTH  170
#define BUTTON_HEIGHT 75
#define BUTTON_X_GAP  25
#define BUTTON_Y_GAP  20
#define MARGIN_LEFT   80

#define BUTTON_WIDTH_PX  170_px
#define BUTTON_HEIGHT_PX 75_px
#define BUTTON_X_GAP_PX  25_px
#define BUTTON_Y_GAP_PX  20_px
#define MARGIN_LEFT_PX   80_px

#define BUTTON1_X_START  (MARGIN_LEFT)
#define BUTTON1_X_END    (MARGIN_LEFT + BUTTON_WIDTH)
#define BUTTON2_X_START  (MARGIN_LEFT + BUTTON_WIDTH + BUTTON_X_GAP)
#define BUTTON2_X_END    (MARGIN_LEFT + BUTTON_WIDTH * 2 + BUTTON_X_GAP)
#define BUTTON3_X_START  (MARGIN_LEFT + BUTTON_WIDTH * 2 + BUTTON_X_GAP * 2)
#define BUTTON3_X_END    (MARGIN_LEFT + BUTTON_WIDTH * 3 + BUTTON_X_GAP * 2)

#define BUTTON1_Y_START    (BUTTON_Y_GAP)
#define BUTTON1_Y_END      (BUTTON_Y_GAP + BUTTON_HEIGHT)
#define BUTTON4_Y_START    (BUTTON_Y_GAP * 2 + BUTTON_HEIGHT)
#define BUTTON4_Y_END      (BUTTON_Y_GAP * 2 + BUTTON_HEIGHT * 2)
#define BUTTON7_Y_START    (BUTTON_Y_GAP * 3 + BUTTON_HEIGHT * 2)
#define BUTTON7_Y_END      (BUTTON_Y_GAP * 3 + BUTTON_HEIGHT * 3)
#define BUTTON_DEL_Y_START (BUTTON_Y_GAP * 4 + BUTTON_HEIGHT * 3)
#define BUTTON_DEL_Y_END   (BUTTON_Y_GAP * 4 + BUTTON_HEIGHT * 4)

static constexpr const teeui::Color kColorBackground = 0xffffff00;

static teeui::Color alfaCombineChannel(uint32_t shift,
                                       double alfa,
                                       teeui::Color a,
                                       teeui::Color b) {
    a >>= shift;
    a &= 0xff;
    b >>= shift;
    b &= 0xff;
    double acc = alfa * a + (1 - alfa) * b;
    if (acc <= 0)
        return 0;
    uint32_t result = acc;
    if (result > 255)
        return 255 << shift;
    return result << shift;
}

template <typename... Elements>
static teeui::Error drawElements(std::tuple<Elements...>& layout,
                                 const teeui::PixelDrawer& drawPixel) {
    // Error::operator|| is overloaded, so we don't get short circuit
    // evaluation. But we get the first error that occurs. We will still try and
    // draw the remaining elements in the order they appear in the layout tuple.
    return (std::get<Elements>(layout).draw(drawPixel) || ...);
}

keyboardView::keyboardView(uint8_t *buffer, uint32_t length, uint32_t width, uint32_t height):
                           buffer_(buffer), length_(length), width_(width), height_(height) {
    teeui::context<teeui::SecureIMEParameters> ctx(6.45211, 400.0 / 412.0);
    ctx.setParam<teeui::ButtonWidth>(BUTTON_WIDTH_PX);
    ctx.setParam<teeui::ButtonHeight>(BUTTON_HEIGHT_PX);
    ctx.setParam<teeui::ButtonXGap>(BUTTON_X_GAP_PX);
    ctx.setParam<teeui::ButtonYGap>(BUTTON_Y_GAP_PX);
    ctx.setParam<teeui::MarginLeft>(MARGIN_LEFT_PX);
    layout_ = instantiateLayout(teeui::SecureIMELayout(), ctx);
}

int keyboardView::renderAndSwap() {
    auto drawPixel = teeui::makePixelDrawer([&](uint32_t x, uint32_t y,
                                                      teeui::Color color)
                                                    -> teeui::Error {
        size_t pos = y * line_stride + x * pixel_stride;
        if (pos >= length_) {
            TLOGE("Out of buffer size! x: %d, y: %d", x, y);
            return teeui::Error::OutOfBoundsDrawing;
        }

        double alfa = (color & 0xff000000) >> 24;
        alfa /= 255.0;
        auto& pixel =
                *reinterpret_cast<teeui::Color*>(buffer_ + pos);

        pixel = alfaCombineChannel(0, alfa, color, pixel) |
                alfaCombineChannel(8, alfa, color, pixel) |
                alfaCombineChannel(16, alfa, color, pixel) |
                (pixel & 0xff000000);
        return teeui::Error::OK;
    });

    /* draw background */
    uint32_t *pixeliter = (uint32_t *)buffer_;
    for(uint32_t i = 0; i < width_ * height_; i++)
        pixeliter[i] = kColorBackground;

    if (auto error = drawElements(layout_, drawPixel)) {
        TLOGE("Element drawing failed: %u\n", error.code());
        return -1;
    }
    return 0;
}

int keyboardView::drawKeyboard() {
    int seed = 0;

    /* make sure display buffer is well initialized! */
    if (buffer_ == nullptr) {
        TLOGE("display buffer is not ready!\n");
        return -1;
    }

    /* keyboard randomization */
    if (trusty_rng_hw_rand((uint8_t *)&seed, sizeof(int)) != 0) {
        TLOGE("Failed to get seed from HW RNG.\n");
        return -1;
    }
    std::shuffle(keyboard_layout.begin(), keyboard_layout.end(), std::default_random_engine(seed));

    /* set keyboard text */
    std::get<teeui::Button0_Text>(layout_).setText({&*keyboard_layout[0].begin(), &*keyboard_layout[0].end()});
    std::get<teeui::Button1_Text>(layout_).setText({&*keyboard_layout[1].begin(), &*keyboard_layout[1].end()});
    std::get<teeui::Button2_Text>(layout_).setText({&*keyboard_layout[2].begin(), &*keyboard_layout[2].end()});
    std::get<teeui::Button3_Text>(layout_).setText({&*keyboard_layout[3].begin(), &*keyboard_layout[3].end()});
    std::get<teeui::Button4_Text>(layout_).setText({&*keyboard_layout[4].begin(), &*keyboard_layout[4].end()});
    std::get<teeui::Button5_Text>(layout_).setText({&*keyboard_layout[5].begin(), &*keyboard_layout[5].end()});
    std::get<teeui::Button6_Text>(layout_).setText({&*keyboard_layout[6].begin(), &*keyboard_layout[6].end()});
    std::get<teeui::Button7_Text>(layout_).setText({&*keyboard_layout[7].begin(), &*keyboard_layout[7].end()});
    std::get<teeui::Button8_Text>(layout_).setText({&*keyboard_layout[8].begin(), &*keyboard_layout[8].end()});
    std::get<teeui::Button9_Text>(layout_).setText({&*keyboard_layout[9].begin(), &*keyboard_layout[9].end()});

    return renderAndSwap();
}

int keyboardView::getKeyboardText(uint32_t x, uint32_t y) {
    int key = -1;

    /* make sure the coordinate is valid */
    if ((x < 0) || (x > width_) || (y < 0) || (y > height_))
        return -1;

    if ((x > BUTTON1_X_START) && (x < BUTTON1_X_END)) {
        if ((y > BUTTON1_Y_START) && (y < BUTTON1_Y_END)) {
            key = *(keyboard_layout[1].c_str()) - '0';
        } else if ((y > BUTTON4_Y_START) && (y < BUTTON4_Y_END)) {
            key = *(keyboard_layout[4].c_str()) - '0';
        } else if ((y > BUTTON7_Y_START) && (y < BUTTON7_Y_END)) {
            key = *(keyboard_layout[7].c_str()) - '0';
        } else if ((y > BUTTON_DEL_Y_START) && (y < BUTTON_DEL_Y_END)) {
            key = BUTTON_DELETE;
        }
    } else if ((x > BUTTON2_X_START) && (x < BUTTON2_X_END)) {
        if ((y > BUTTON1_Y_START) && (y < BUTTON1_Y_END)) {
            key = *(keyboard_layout[2].c_str()) - '0';
        } else if ((y > BUTTON4_Y_START) && (y < BUTTON4_Y_END)) {
            key = *(keyboard_layout[5].c_str()) - '0';
        } else if ((y > BUTTON7_Y_START) && (y < BUTTON7_Y_END)) {
            key = *(keyboard_layout[8].c_str()) - '0';
        } else if ((y > BUTTON_DEL_Y_START) && (y < BUTTON_DEL_Y_END)) {
            key = *(keyboard_layout[0].c_str()) - '0';
        }
    } else if ((x > BUTTON3_X_START) && (x < BUTTON3_X_END)) {
        if ((y > BUTTON1_Y_START) && (y < BUTTON1_Y_END)) {
            key = *(keyboard_layout[3].c_str()) - '0';
        } else if ((y > BUTTON4_Y_START) && (y < BUTTON4_Y_END)) {
            key = *(keyboard_layout[6].c_str()) - '0';
        } else if ((y > BUTTON7_Y_START) && (y < BUTTON7_Y_END)) {
            key = *(keyboard_layout[9].c_str()) - '0';
        } else if ((y > BUTTON_DEL_Y_START) && (y < BUTTON_DEL_Y_END)) {
            key = BUTTON_CANCEL;
        }
    }

    return key;
}
