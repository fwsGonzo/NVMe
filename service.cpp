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
//1 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <os>
#include <fs/disk.hpp>
static std::shared_ptr<fs::Disk> disk;

static void test_filesystem();

#include <kernel/pci_manager.hpp>
void Service::start(const std::string&)
{
  PCI_manager::init(1);

  // instantiate memdisk with FAT filesystem
  auto& device = hw::Devices::drive(0);
  disk = std::make_shared<fs::Disk> (device);
  // assert that we have a disk
  CHECKSERT(disk, "Disk created");
  // if the disk is empty, we can't mount a filesystem
  CHECKSERT(!disk->empty(), "Disk not empty");
  CHECKSERT(disk->dev().size() == 1, "Disk has 1 sector");
  /*
  INFO2("|-> Sync reads");
  int gucci = 0;
  for (int i = 0; i < 1000; i++) {
    auto buffer = disk->dev().read_sync(0, 1);
    if (buffer != nullptr)
    if (buffer->size() == device.block_size()) gucci ++;
  }
  CHECKSERT(gucci == 1000, "1000x read_sync() success");
  */
  
  static const int NUM_ASYNC  = 100;
  INFO2("|-> Async reads");
  for (int i = 0; i < NUM_ASYNC; i++)
  disk->dev().read(0,
    [&device] (auto buffer) {
      static int gucci = 0;
      if (buffer != nullptr)
      if (buffer->size() == device.block_size()) gucci ++;
      assert(buffer != nullptr);
      assert(buffer->size() == device.block_size());

      if (gucci == NUM_ASYNC)
      {
        INFO2("[x] %dx async read() success", NUM_ASYNC);
        INFO2("SUCCESS");
        OS::shutdown();
      }
    });
}

static void list_partitions(decltype(disk) disk)
{
  disk->partitions([] (fs::error_t err, auto& parts)
  {
      CHECKSERT (not err, "Was able to fetch partition table");
      for (auto& part : parts)
        printf("[Partition]  '%s' at LBA %u\n",
               part.name().c_str(), part.lba());
  });
}

static void test_filesystem()
{
  // list extended partitions
  list_partitions(disk);

  // Initialize first valid partition (auto-detect and init)
  disk->init_fs(
  [] (fs::error_t err, auto& fs)
  {
    if (err) {
      printf("Could not mount filesystem\n");
      panic("init_fs() failed");
    }
    CHECKSERT (not err, "Was able to mount filesystem");

    // async ls
    fs.ls("/",
    [] (fs::error_t err, auto ents) {
      if (err) {
        printf("Could not list '/' directory\n");
        panic("ls() failed");
      }

      // go through directory entries
      for (auto& e : *ents)
      {
        printf("%s: %s\t of size %lu bytes (CL: %lu)\n",
               e.type_string().c_str(), e.name().c_str(), e.size(), e.block());
        if (e.is_file())
        {
          printf("*** Read %s\n", e.name().c_str());
          disk->fs().read(
            e,
            0,
            e.size(),
            [e_name = e.name()]
            (fs::error_t err, fs::buffer_t buffer)
            {
              if (err) {
                printf("Failed to read %s!\n", e_name.c_str());
                panic("read() failed");
              }

              std::string contents((const char*) buffer->data(), buffer->size());
              printf("[%s contents]:\n%s\nEOF\n\n",
                     e_name.c_str(), contents.c_str());
              // ---
              INFO("Virtioblk Test", "SUCCESS");
            }
          );
        } // is_file
      } // ents
    }); // ls
  }); // disk->init_fs()
}
