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
#include <hw/writable_blkdev.hpp>
#include <hw/pci_device.hpp>
#include <deque>
#include "nvme_regs.hpp"

class NVMe : public hw::Writable_Block_device
{
public:
  static std::unique_ptr<Block_device> new_instance(hw::PCI_Device& d)
  { return std::make_unique<NVMe>(d); }

  std::string device_name() const override {
    return "nvme" + std::to_string(id());
  }

  /** Human readable name. */
  const char* driver_name() const noexcept override {
    return "NVMe";
  }

  // returns the optimal block size for this block device
  block_t block_size() const noexcept override;

  // returns number of blocks on disk
  block_t size() const noexcept override;

  // read @blk + @cnt from disk, call @cb with buffer when done
  void read(block_t blk, size_t cnt, on_read_func cb) override;
  buffer_t read_sync(block_t, size_t) override;

  // write starting at @blk from @buffer, call @callback when done
  void write(block_t, buffer_t, on_write_func callback) override;
  bool write_sync(block_t, buffer_t) override;

  void deactivate() override;

  NVMe(hw::PCI_Device& pcidev);

  typedef uint32_t queue_reference;
private:
  enum {
    MODE_READ, MODE_WRITE
  };
  struct work_item
  {
    on_read_func  on_read  = nullptr;
    on_write_func on_write = nullptr;
    buffer_t buffer = nullptr;
    block_t  blk;
    size_t   cnt;
    int      mode = MODE_WRITE;
    bool     async = false;
  };
  
  struct async_result {
    on_read_func  on_read  = nullptr;
    on_write_func on_write = nullptr;
    int      mode   = MODE_WRITE;
    buffer_t buffer = nullptr;
    queue_reference uid = 0;
  };

  struct sync_result {
    int      status = 0;
    uint32_t result = 0;
    bool good() const noexcept { return status == 0; }
  };
  struct queue;
  struct namespace_t {
    namespace_t(NVMe&, queue&, uint32_t nsid);
    uint32_t nsid() const noexcept { return m_nsid; }
    uint64_t block_size() const noexcept { return m_blk_size; }
    uint64_t blocks() const noexcept { return m_blocks; }
    
  private:
    NVMe&    m_dev;
    uint32_t m_nsid;
    uint64_t m_blk_size;
    uint64_t m_blocks;
  };
  struct queue_ring {
    void*     m_data = nullptr;
    uint16_t  no;
    uint16_t  size;
    uint16_t  index = 0; // head/tail
    int16_t   current_phase = 0x1;
    
    nvme_command& command(uint16_t idx, const uint32_t stride);
    nvme_io_comp_entry& comp_entry() noexcept;
    void advance_head(NVMe& dev) noexcept;
    void alloc(uint16_t, uint16_t size, size_t elem);
  };
  struct queue
  {
    queue(NVMe& dev) : m_dev(dev) {}
    queue(NVMe&, int no, uint16_t subm_size, uint16_t comp_size);

    bool full() const noexcept { return level == comp.size; }
    void comp_advance_head() noexcept;

    sync_result identify(uint32_t nsid, uint32_t cns, void* dma_addr);
    sync_result set_features(uint32_t fid, uint32_t dw11, void* dma_addr);
    sync_result create_ioq(uint32_t nsid);
    nvme_command read(uint32_t nsid, void*, uint64_t lba, uint16_t blks);
    nvme_command write(uint32_t nsid, void*, uint64_t lba, uint16_t blks);
    void        identify_namespaces();
    void        submit(nvme_command&);
    void        submit_async(nvme_command&, async_result);
    sync_result submit_sync(nvme_command&);
    queue_reference self_reference() const noexcept;
    void handle_result(const nvme_io_comp_entry&);
    void attach_namespace(const uint32_t nsid);

    queue_ring subm;
    queue_ring comp;
    std::vector<namespace_t> ns;
    std::deque<work_item> writeq;
  private:
    NVMe& m_dev;
    uint16_t id_counter = 1;
    uint16_t level = 0;
  };

  void schedule(work_item);
  buffer_t begin_read(work_item);
  bool     begin_write(work_item);

  void check_version();
  void retrieve_information();
  void setup_io_queues();
  void msix_aq_comp_handler();
  void msix_ioq_comp_handler();
  void handle_queue(queue&);

  inline uint32_t read32(uint32_t off) noexcept;
  inline uint64_t read64(uint32_t off) noexcept;
  inline void write32(uint32_t off, uint32_t val) noexcept;
  inline void write64(uint32_t off, uint64_t val) noexcept;

  hw::PCI_Device& m_pcidev;

  uintptr_t m_ctl = 0;
  uint32_t  m_dbstride;
  queue   m_aq;
  std::vector<queue> m_ioqs;
  std::deque<async_result> async_results;

  // stat counters
  uint32_t* m_errors   = nullptr;
  uint32_t* m_requests = nullptr;
};

#endif
