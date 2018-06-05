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

NVMe::NVMe(hw::PCI_Device& dev)
  : m_pcidev(dev)
{
  INFO("NVMe", "Initializing");
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
  dev.probe_resources();
  dev.parse_capabilities();

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

  this->m_dbstride = read32(REG_CAP) & 0xF00000000; // 32-35
  printf("Doorbell stride: %u bytes\n", (1 << (2 + this->m_dbstride)));

  // start device
  write32(REG_CTLCFG, read32(REG_CTLCFG) | CFG_EN);

  uint32_t status;
  do {
    status = read32(REG_CTLSTA);
  } while ((status & 0x3) == 0);
  if (status & 0x2) {
    printf("Failed to start NVMe device, ready = %d\n", status & 1);
    assert(0 && "NVMe fatal status");
  }
  assert(status & 0x1);

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

#include <kernel/pci_manager.hpp>
__attribute__((constructor))
static void nvme_gconstr() {
  // QEMU NVM Express Controller
  PCI_manager::register_blk(PCI::VENDOR_INTEL, 0x5845, &NVMe::new_instance);
}
