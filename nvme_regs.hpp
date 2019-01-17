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

enum {
  NVME_CMD_CREATE_SQ     = 0x01,
  NVME_CMD_GET_LOG_PAGE  = 0x02,
  NVME_CMD_CREATE_CQ     = 0x05,
  NVME_CMD_ABORT         = 0x08,
  NVME_CMD_IDENTIFY      = 0x06,
  NVME_CMD_SET_FEATURES  = 0x09,
  NVME_CMD_GET_FEATURES  = 0x0A,
  NVME_CMD_DEV_SELF_TEST = 0x14,

  NVME_IO_FLUSH          = 0x0,
  NVME_IO_WRITE          = 0x1,
  NVME_IO_READ           = 0x2,
  NVME_IO_WRITE_UNCOR    = 0x4,
  NVME_IO_COMPARE        = 0x5,
  NVME_IO_WRITE_ZEROES   = 0x8,

  NVME_FEAT_NUM_QUEUES  = 0x07,
  NVME_FEAT_IRQ_CONFIG  = 0x09,
  
  NVME_QUEUE_PHYS_CONTIG = (1 << 0),
  NVME_CQ_IRQ_ENABLED    = (1 << 1)
};

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
static_assert(sizeof(nvme_io_subm_entry) == 56, "I/O subm entry must be 56 bytes");

struct nvme_identify {
	uint64_t  resv1[2];
	uint64_t  prp1;
	uint64_t  prp2;
	int32_t   cns;
	uint32_t  resv2[5];
};
static_assert(sizeof(nvme_identify) == 56, "Identify cmd must be 56 bytes");

struct nvme_features {
	uint64_t  resv1[2];
	uint64_t  prp1;
	uint64_t  prp2;
	uint32_t  fid;
	uint32_t  dw11;
	uint32_t  resv2[4];
};
static_assert(sizeof(nvme_features) == 56, "Features cmd must be 56 bytes");

struct nvme_create_cq {
	uint32_t resv1[4];
	uint64_t prp1;
  uint64_t resv2;
  uint16_t cq_id;
  uint16_t cq_size;
  uint16_t cq_flags;
  uint16_t cq_vector;
	uint32_t resv3[4];
};

struct nvme_create_sq {
	uint32_t resv1[4];
	uint64_t prp1;
	uint64_t resv2;
  uint16_t sq_id;
  uint16_t sq_size;
  uint16_t sq_flags;
  uint16_t sq_cqid;
	uint32_t resv3[4];
};

struct nvme_readwrite
{
	uint64_t  resv;
	uint64_t  metadata;
	uint64_t  prp1;
	uint64_t  prp2;
	uint64_t  slba;
	uint16_t  length;
	uint16_t  control;
	uint32_t  dsmgmt;
	uint32_t  reftag;
	uint16_t  apptag;
  uint16_t  appmask;
};
static_assert(sizeof(nvme_readwrite) == 56, "Read/write cmd must be 56 bytes");

struct nvme_command
{
  uint8_t   opcode;
	uint8_t   flags;
	uint16_t	cmd_id;
	uint32_t  nsid;
  union {
    nvme_io_subm_entry entry;
    nvme_identify      ident;
    nvme_features      features;
    nvme_create_sq     create_sq;
    nvme_create_cq     create_cq;
    nvme_readwrite     rw;
  };

  nvme_command()
  {
    std::memset(this, 0, sizeof(nvme_command));
  }
};
static_assert(sizeof(nvme_command) == 64, "NVMe command size must match its components");

struct nvme_io_comp_entry
{
  uint32_t result;
  uint32_t resv;
  uint16_t sq_head;
  uint16_t sq_id;
  uint16_t cmd_id;
  int16_t  status;

  int16_t phase_tag() const noexcept {
    return status & 0x1;
  }
  int16_t error() const noexcept {
    return (status >> 1) & 0x7FFF;
  }
  int error_code() const noexcept {
    return error() & 0x3FFF;
  }
  int error_dnr() const noexcept {
    return error() & 0x4000;
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

struct identify_ctrl_data {
  uint16_t vid;
  uint16_t ssvid;
  char     serial_number[20];
  char     model_number[40];
  char     firmware_rev[8];
  uint8_t  rab;
  uint8_t  ieee[3];
  uint8_t  mic;
  uint8_t  mdts;
  uint16_t cntlid;
  uint32_t ver;
  uint32_t resv1[172];
  uint16_t oacs;
  uint8_t  acl;
  uint8_t  aerl;
  uint8_t  frmw;
  uint8_t  lpa;
  uint8_t  elpe;
  uint8_t  npss;
  uint8_t  avscc;
  uint8_t  apsta;
  uint16_t wstemp;
  uint16_t cctemp;
  uint8_t  resv2[242];
  uint8_t  sqes;
  uint8_t  cqes;
  uint8_t  resv3[2];
  uint32_t nn;
  uint16_t oncs;
  uint16_t fuses;
  uint8_t  fna;
  uint8_t  vwc;
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
