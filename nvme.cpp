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

#include "nvme.hpp"

#include <kernel/events.hpp>
#include <statman>
#include <fs/common.hpp>
#include <hw/pci.hpp>
#include <cassert>
#include "nvme_regs.hpp"

#define NVME_RESET_VALUE  0x4E564D65 /* "NVMe" */

NVMe::NVMe(hw::PCI_Device& dev)
  : m_pcidev(dev)
{
  INFO("NVMe", "Initializing");
  dev.probe_resources();
  dev.parse_capabilities();
  {
    auto& reqs = Statman::get().create(
      Stat::UINT32, device_name() + ".requests");
    this->m_requests = &reqs.get_uint32();
    *this->m_requests = 0;

    auto& err = Statman::get().create(
      Stat::UINT32, device_name() + ".errors");
    this->m_errors = &err.get_uint32();
    *this->m_errors = 0;
  }

  if (dev.msix_cap())
  {
    dev.init_msix();
    INFO2("Found %u MSI-x vectors", dev.get_msix_vectors());
    //assert(dev.get_msix_vectors() >= 1);
    uint8_t iocq = Events::get().subscribe({this, &NVMe::msix_cmd_handler});
    dev.setup_msix_vector(SMP::cpu_id(), iocq);
    uint8_t cmpq = Events::get().subscribe({this, &NVMe::msix_comp_handler});
    dev.setup_msix_vector(SMP::cpu_id(), cmpq);
  }
  else {
    assert(0 && "No intx support for NVMe");
  }

  // controller registers BAR
  this->m_ctl = dev.get_bar(0).start;
  // verify NVM express version
  check_version();

  this->m_dbstride = (read64(REG_CAP) >> 32) & 0xF; // 32-35
  const size_t dbstride_bytes = 1 << (2 + this->m_dbstride);
  printf("Doorbell stride: %u raw %zu bytes\n", this->m_dbstride, dbstride_bytes);

  // reset device
  write32(REG_CTLCFG, read32(REG_CTLCFG) & ~CFG_EN);
  //write32(REG_NVMSSR, NVME_RESET_VALUE);

  // create queues
  write32(REG_AQ_CFG,
      COMP_Q_SIZE << 16 |
      SUBM_Q_SIZE << 0  );

  m_adm_sq.data = std::aligned_alloc(4096, dbstride_bytes * SUBM_Q_SIZE);
  m_adm_sq.size = SUBM_Q_SIZE;
  write64(REG_AQ_SUBM_BA, (uint64_t) m_adm_sq.data);
  m_adm_cq.data = std::aligned_alloc(4096, dbstride_bytes * COMP_Q_SIZE);
  m_adm_cq.size = COMP_Q_SIZE;
  write64(REG_AQ_COMP_BA, (uint64_t) m_adm_cq.data);

  // configure & start device
  write32(REG_CTLCFG,
      4 << 20 | // compq entry exponent (16 bytes)
      6 << 16 | // submq entry exponent (64 bytes)
      0 << 11 | // round robin arbitration
      0 << 7  | // host page size (2^12)
      0 << 4  | // NVM command set
      CFG_EN);  // start device

  uint32_t status;
  do {
    asm("pause");
    status = read32(REG_CTLSTA);
  } while ((status & 0x3) == 0);
  if (status & 0x2) {
    printf("Failed to start NVMe device, ready = %d\n", status & 1);
    assert(0 && "NVMe fatal status");
  }
  assert(status & 0x1);

  // reset aq pointers (?)
  write32(reg_doorbell_submq_tail(0, m_dbstride), m_adm_sq.index);
  write32(reg_doorbell_compq_head(0, m_dbstride), m_adm_cq.index);

  // identify
  printf("Identify command...\n");
  nvme_io_subm_entry idtfy;
  idtfy.command = NVME_CMD_IDENTIFY;
  idtfy.prp1    = (uint64_t) std::aligned_alloc(4096, 4096);
  this->submit(m_adm_sq, idtfy);

  INFO("NVMe", "Block device with %zu sectors capacity", 0ul);
}

void NVMe::check_version()
{
  const uint32_t reg = read32(REG_VER);
  const uint16_t major = reg >> 16;
  const uint16_t minor = (reg >> 8) & 0xFF;
  INFO2("NVM Express v%u.%u", major, minor);
  assert(major == 1);
  assert(minor == 0 || minor == 1 || minor == 2 || minor == 3);
}

void NVMe::msix_cmd_handler()
{
  printf("NVMe::msix_cmd_handler()\n");
}
void NVMe::msix_comp_handler()
{
  printf("NVMe::msix_comp_handler()\n");
}

void NVMe::read(block_t blk, on_read_func func)
{
  func(nullptr);
}
void NVMe::read(block_t blk, size_t cnt, on_read_func func)
{
  func(nullptr);
}

void NVMe::deactivate()
{
  /// TODO: reset device
}

uint32_t NVMe::read32(const uint32_t off) noexcept
{
  assert((off & 3) == 0);
  return *(volatile uint32_t*) (this->m_ctl + off);
}
void NVMe::write32(const uint32_t off, const uint32_t val) noexcept
{
  assert((off & 3) == 0);
  *(volatile uint32_t*) (this->m_ctl + off) = val;
}
uint64_t NVMe::read64(const uint32_t off) noexcept
{
  assert((off & 7) == 0);
  return *(volatile uint64_t*) (this->m_ctl + off);
}
void NVMe::write64(const uint32_t off, const uint64_t val) noexcept
{
  assert((off & 7) == 0);
  *(volatile uint64_t*) (this->m_ctl + off) = val;
}

void NVMe::submit(queue_t& q, const nvme_io_subm_entry& cmd)
{
  // write entry to queue area
  *(nvme_io_subm_entry*) ((char*) q.data + q.index * m_dbstride) = cmd;

  // update tail pointer
  q.index = (q.index + 1) % SUBM_Q_SIZE;
  write32(reg_doorbell_submq_tail(q.no, m_dbstride), q.index);
}


#include <kernel/pci_manager.hpp>
__attribute__((constructor))
static void nvme_gconstr() {
  // QEMU NVM Express Controller
  PCI_manager::register_blk(PCI::VENDOR_INTEL, 0x5845, &NVMe::new_instance);
}
