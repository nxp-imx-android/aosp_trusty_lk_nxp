/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <devices/device_parameters.h>
#include <optional>
#include <imx-regs.h>
namespace devices {

using namespace teeui;

int getDisplayCount() {
     return 1;
}

std::optional<context<ConUIParameters>> getDisplayContext(int display_index,
                                                         bool magnified) {

    if (display_index != 0) {
        return std::nullopt;
    }

    context<ConUIParameters> ctx(6.45211, 400.0 / 412.0);
#if defined(MACH_IMX8ULP)
    ctx.setParam<RightEdgeOfScreen>(720_px);
    ctx.setParam<BottomOfScreen>(1280_px);
#else
    ctx.setParam<RightEdgeOfScreen>(1920_px);
    ctx.setParam<BottomOfScreen>(1080_px);
#endif
    ctx.setParam<PowerButtonTop>(20.26_mm);
    ctx.setParam<PowerButtonBottom>(30.26_mm);
    ctx.setParam<VolUpButtonTop>(40.26_mm);
    ctx.setParam<VolUpButtonBottom>(50.26_mm);

    if (magnified) {
        ctx.setParam<DefaultFontSize>(38_dp);
        ctx.setParam<BodyFontSize>(30_dp);
    } else {
        ctx.setParam<DefaultFontSize>(34_dp);
        ctx.setParam<BodyFontSize>(36_dp);
    }
    return {ctx};
}

std::optional<std::unique_ptr<layouts::ILayout>> getDisplayLayout(
    int display_index,
    bool inverted,
    const context<ConUIParameters>& ctx) {
    if (display_index != 0) {
        return std::nullopt;
    }
    return std::make_unique<teeui::layouts::DisplayLayout>(inverted, ctx);
 }

}  // namespace devices
