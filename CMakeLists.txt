cmake_minimum_required(VERSION 3.0)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
project (hello_world)
include(${CMAKE_CURRENT_BINARY_DIR}/conanbuildinfo.cmake OPTIONAL RESULT_VARIABLE HAS_CONAN)
conan_basic_setup()
include(os)

set(SOURCES
		service.cpp
		nvme.cpp
	)

os_add_executable(nvme "NVMe Driver Repo" ${SOURCES})
#os_add_drivers(nvme virtionet vmxnet3 boot_logger)
os_add_stdout(nvme default_stdout)
