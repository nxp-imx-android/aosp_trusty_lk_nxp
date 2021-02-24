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

namespace devices {

using namespace teeui;

context<ConUIParameters> getDeviceContext(bool magnified) {
    context<ConUIParameters> ctx(6.45211, 400.0 / 412.0);
    ctx.setParam<RightEdgeOfScreen>(1920_px);
    ctx.setParam<BottomOfScreen>(1080_px);
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
    return ctx;
}

}  // namespace devices
