// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2015 Oslo and Akershus University College of Applied Sciences
// and Alfred Bratterud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#define REG_CAP    0x00
#define REG_VER    0x08
#define REG_INTMS  0x0C
#define REG_INTMC  0x10
#define REG_CTLCFG 0x14
#define REG_CTLSTA 0x1C

#define REG_COMPQ_HEAD  0x1000
#define REG_SUBMQ_TAIL  0x1000

inline uint32_t reg_doorbell_compq_head(int y, const int stride) {
  return REG_COMPQ_HEAD + ((2*y + 1) * (4 << stride));
}
inline uint32_t reg_doorbell_compq_tail(int y, const int stride) {
  return REG_SUBMQ_TAIL + ((2*y + 0) * (4 << stride));
}

#define CFG_EN   0x1
