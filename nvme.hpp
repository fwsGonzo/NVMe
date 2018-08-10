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
#ifndef NVM_EXPRESS_HPP
#define NVM_EXPRESS_HPP

#include <common>
#include <hw/block_device.hpp>
#include <hw/pci_device.hpp>
#include <deque>

struct nvme_io_subm_entry;

class NVMe : public hw::Block_device
{
public:
  static std::unique_ptr<Block_device> new_instance(hw::PCI_Device& d)
  { return std::make_unique<NVMe>(d); }

  static constexpr size_t SECTOR_SIZE = 512;

  std::string device_name() const override {
    return "nvme" + std::to_string(id());
  }

  /** Human readable name. */
  const char* driver_name() const noexcept override {
    return "NVMe";
  }

  // returns the optimal block size for this device
  block_t block_size() const noexcept override {
    return SECTOR_SIZE; // some multiple of sector size
  }

  block_t size() const noexcept override {
    return 0;
  }

  // read @blk from disk, call func with buffer when done
  void read(block_t blk, on_read_func func) override;
  // read @blk + @cnt from disk, call func with buffer when done
  void read(block_t blk, size_t cnt, on_read_func cb) override;

  // unsupported sync reads
  buffer_t read_sync(block_t) override {
    return buffer_t();
  }
  buffer_t read_sync(block_t, size_t) override {
    return buffer_t();
  }

  // not supported
  void write(block_t, buffer_t, on_write_func callback) override {
    callback(true);
  }
  bool write_sync(block_t, buffer_t) override { return true; };

  void deactivate() override;

  NVMe(hw::PCI_Device& pcidev);

private:
  static const int SUBM_Q_SIZE = 16;
  static const int COMP_Q_SIZE = 16;

  struct queue_t {
    void*    data = nullptr;
    uint16_t no;
    uint16_t size;
    uint16_t index = 0;
  };

  void check_version();
  void msix_cmd_handler();
  void msix_comp_handler();
  void submit(queue_t&, const nvme_io_subm_entry&);

  inline uint32_t read32(uint32_t off) noexcept;
  inline uint64_t read64(uint32_t off) noexcept;
  inline void write32(uint32_t off, uint32_t val) noexcept;
  inline void write64(uint32_t off, uint64_t val) noexcept;

  hw::PCI_Device& m_pcidev;

  uintptr_t m_ctl = 0;
  uint32_t  m_dbstride;

  queue_t m_adm_sq;
  queue_t m_adm_cq;

  // stat counters
  uint32_t* m_errors   = nullptr;
  uint32_t* m_requests = nullptr;
};

#endif
