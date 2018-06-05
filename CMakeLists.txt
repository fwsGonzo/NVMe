cmake_minimum_required(VERSION 2.8.9)

if (NOT DEFINED ENV{INCLUDEOS_PREFIX})
  set(ENV{INCLUDEOS_PREFIX} /usr/local)
endif()

include($ENV{INCLUDEOS_PREFIX}/includeos/pre.service.cmake)
project (service)

set(SERVICE_NAME "NVMe driver")
set(BINARY       "nvme")
set(SOURCES
    service.cpp
    nvme.cpp
  )

set(DRIVERS
    boot_logger
  )

include($ENV{INCLUDEOS_PREFIX}/includeos/post.service.cmake)
