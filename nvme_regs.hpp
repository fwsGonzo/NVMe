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
#define REG_NVMSSR 0x20

#define CFG_EN   0x1

#define ADMIN_Q         0
#define REG_AQ_CFG      0x24
#define REG_AQ_SUBM_BA  0x28
#define REG_AQ_COMP_BA  0x30

#define REG_COMPQ_HEAD  0x1000
#define REG_SUBMQ_TAIL  0x1000

#define NVME_CMD_CREATE_SQ     0x01
#define NVME_CMD_GET_LOG_PAGE  0x02
#define NVME_CMD_CREATE_CQ     0x05
#define NVME_CMD_ABORT         0x08
#define NVME_CMD_IDENTIFY      0x06
#define NVME_CMD_SET_FEATURES  0x09
#define NVME_CMD_GET_FEATURES  0x0A
#define NVME_CMD_DEV_SELF_TEST 0x14

#define SGL_TYPE_DEFAULT  0x0

struct sgl_data_block_desc
{
  uint64_t addr   = 0x0;
  uint32_t length = 0;
  uint8_t  padding[3] = {0};
  uint8_t  type = SGL_TYPE_DEFAULT;
};

struct nvme_io_subm_entry
{
  uint8_t  opcode  = 0;
  uint8_t  options = 0; /* No FUSE, PRP */
  uint16_t command = 0;
  uint32_t nsid    = 0;
  uint64_t resv0   = 0;
  uint64_t MPTR = 0x0;
  uint64_t prp1 = 0x0;
  uint64_t prp2 = 0x0;
  uint32_t dw10;
  uint32_t dw11;
  uint32_t dw12;
  uint32_t dw13;
  uint32_t dw14;
  uint32_t dw15;
} __attribute__((packed));
static_assert(sizeof(nvme_io_subm_entry) == 64, "I/O submission entry must be 64 bytes");

struct nvme_io_comp_entry
{
  uint32_t command;
  uint32_t resv;
  uint16_t sq_head;
  uint16_t sq_id;
  uint32_t dw3;

  uint16_t phase_tag() const noexcept {
    return (dw3 >> 16) & 0x1;
  }
  uint16_t status_field() const noexcept {
    return dw3 >> 17;
  }
  uint16_t status_code() const noexcept {
    return status_field() & 0xFF;
  }
  uint16_t cid() const noexcept {
    return dw3 & 0xFFFF;
  }

  bool good() const noexcept {
    return status_code() == 0;
  }

} __attribute__((packed));
static_assert(sizeof(nvme_io_comp_entry) == 16, "I/O submission entry must be 16 bytes");

inline uint32_t reg_doorbell_compq_head(int y, const int stride) {
  return REG_COMPQ_HEAD + ((2*y + 1) * (4 << stride));
}
inline uint32_t reg_doorbell_submq_tail(int y, const int stride) {
  return REG_SUBMQ_TAIL + ((2*y + 0) * (4 << stride));
}

struct identify_lba_format_data {
  uint16_t MS;
  uint8_t  LBADS;
  unsigned RP : 2;
  unsigned Reserved0 : 6;
};

struct identify_namespace_data {
  uint64_t NSZE;
  uint64_t NCAP;
  uint64_t NUSE;
  uint8_t  NSFEAT;
  uint8_t  NLBAF;
  uint8_t  FLBAS;
  uint8_t  MC;
  uint8_t  DPC;
  uint8_t  DPS;
  uint8_t  NMIC;
  uint8_t  RESCAP;
  uint8_t  FPI;
  uint8_t  DLFEAT;
  uint16_t NAWUN;
  uint16_t NAWUPF;
  uint16_t NACWU;
  uint16_t NABSN;
  uint16_t NABO;
  uint16_t NABSPF;
  uint16_t NOIOB;
  uint8_t  NVMCAP[16];
  uint8_t  Reserved0[40];
  uint8_t  NGUID[16];
  uint64_t EUI64;
  identify_lba_format_data LBAF[16];
};
