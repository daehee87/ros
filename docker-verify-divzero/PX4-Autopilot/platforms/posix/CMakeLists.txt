############################################################################
#
#   Copyright (c) 2021 Technology Innoavation Institute. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# 3. Neither the name PX4 nor the names of its contributors may be
#    used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
# OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
############################################################################


px4_add_git_submodule(TARGET git_monocypher PATH "monocypher")
px4_add_git_submodule(TARGET git_libtomcrypt PATH "libtomcrypt")
px4_add_git_submodule(TARGET git_libtommath PATH "libtommath")

px4_add_library(monocypher
	monocypher/src/monocypher.c
	monocypher/src/optional/monocypher-ed25519.c
)

target_include_directories(monocypher
	PUBLIC
		${CMAKE_CURRENT_SOURCE_DIR}/monocypher/src
)

# There is a one shadow warning in monocypher 3.1.2, ignore it
target_compile_options(monocypher PRIVATE -Wno-shadow)



file(GLOB TOMMATH_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "libtommath/*.c")
px4_add_library(libtommath
  ${TOMMATH_SRC}
)


file(GLOB_RECURSE PK_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "libtomcrypt/src/pk/*.c")
file(GLOB_RECURSE MATH_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "libtomcrypt/src/math/*.c")

px4_add_library(libtomcrypt
libtomcrypt_wrappers.c
	${PK_SRC}
	${MATH_SRC}
	libtomcrypt/src/hashes/sha2/sha256.c
	libtomcrypt/src/hashes/helper/hash_memory.c
	libtomcrypt/src/prngs/sprng.c
	libtomcrypt/src/misc/crypt/crypt_ltc_mp_descriptor.c
	libtomcrypt/src/misc/crypt/crypt_hash_is_valid.c
	libtomcrypt/src/misc/crypt/crypt_prng_is_valid.c
	libtomcrypt/src/misc/zeromem.c
)

target_include_directories(libtomcrypt
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/libtommath
        )

target_include_directories(libtomcrypt
	PUBLIC
		${CMAKE_CURRENT_SOURCE_DIR}/libtomcrypt/src/headers
)

# libtomcrypt defines:
# ARGTYPE=3: No argument checking
add_definitions(-DARGTYPE=3 -DLTC_EASY -DLTC_NO_TEST -DLTM_DESC -DMP_LOW_MEM)

# link to libtommath and os provided random library
target_link_libraries(libtomcrypt
	PRIVATE
		libtommath
		px4_random
)

# Fix for erroneous warning on some compilers:
# "der_encode_asn1_identifier.c:39:18: error: comparison is always false due to limited range of data type"
target_compile_options(libtomcrypt PRIVATE -Wno-type-limits)

# Re-define memory allocation macros if we are building for
# memory protected build in nuttx. All allocations happen in
# kernel heap there

if (NOT DEFINED CONFIG_BUILD_FLAT AND "${PX4_PLATFORM}" MATCHES "nuttx")
	target_compile_options(libtomcrypt PUBLIC -DXMALLOC=kmm_malloc -DXFREE=kmm_free -DXREALLOC=kmm_realloc -DXCALLOC=kmm_calloc)
	target_compile_options(libtommath PUBLIC -DMP_MALLOC=kmm_malloc -DMP_FREE\(p,s\)=kmm_free\(p\) -DMP_REALLOC\(p,o,n\)=kmm_realloc\(p,n\) -DMP_CALLOC=kmm_calloc)
	target_link_libraries(libtommath PRIVATE nuttx_kmm)
endif()





include_directories(${CMAKE_CURRENT_BINARY_DIR})

get_property(module_libraries GLOBAL PROPERTY PX4_MODULE_LIBRARIES)

# When building with catkin, do not change CMAKE_RUNTIME_OUTPUT_DIR from
# CMAKE_CURRENT_BINARY_DIR ''./platforms/posix' to './bin'
if (NOT CATKIN_DEVEL_PREFIX)
	set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
	set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin)
	set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin)
endif()

set(PX4_SHELL_COMMAND_PREFIX "px4-")

add_definitions("-DPX4_SHELL_COMMAND_PREFIX=\"${PX4_SHELL_COMMAND_PREFIX}\"")

px4_posix_generate_builtin_commands(
	OUT apps
	MODULE_LIST ${module_libraries})

px4_posix_generate_alias(
	OUT ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/px4-alias.sh
	MODULE_LIST ${module_libraries}
	PREFIX ${PX4_SHELL_COMMAND_PREFIX}
)

if (CMAKE_BUILD_TYPE STREQUAL FuzzTesting)
	add_executable(px4
		src/px4/common/main_fuzztesting.cpp
		apps.cpp
		)
else()
	add_executable(px4
		src/px4/common/main.cpp
		apps.cpp
		)
endif()

target_link_libraries(px4
	PRIVATE
		${module_libraries}
		m
		parameters
)

if((NOT APPLE) AND (NOT ANDROID))
	target_link_libraries(px4 PRIVATE rt)
endif()

if(NOT ANDROID)
	target_link_libraries(px4 PRIVATE pthread)
endif()

target_link_libraries(px4 PRIVATE uORB)

if (CMAKE_BUILD_TYPE STREQUAL FuzzTesting)
	target_include_directories(px4 PRIVATE SYSTEM "${CMAKE_BINARY_DIR}/mavlink}")
	target_compile_options(px4 PRIVATE "-Wno-cast-align")
endif()

#=============================================================================
# install
#

# TODO: extend to snapdragon

# px4 dirs
install(
	DIRECTORY
		${PROJECT_SOURCE_DIR}/posix-configs
		${PROJECT_SOURCE_DIR}/test
		${CMAKE_BINARY_DIR}/etc
		${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
	DESTINATION
		${PROJECT_NAME}
	USE_SOURCE_PERMISSIONS
)

# Module Symlinks
px4_posix_generate_symlinks(
	MODULE_LIST ${module_libraries}
	PREFIX ${PX4_SHELL_COMMAND_PREFIX}
	TARGET px4
)

if (config_romfs_root)
	add_subdirectory(${PX4_SOURCE_DIR}/ROMFS ${PX4_BINARY_DIR}/ROMFS)
	add_dependencies(px4 romfs_gen_files_target)
endif()


# board defined upload helper
if(EXISTS "${PX4_BOARD_DIR}/cmake/upload.cmake")
	include(${PX4_BOARD_DIR}/cmake/upload.cmake)
endif()


if("${PX4_BOARD}" MATCHES "beaglebone_blue")
	target_link_libraries(px4 PRIVATE robotics_cape)

elseif("${PX4_BOARD}" MATCHES "emlid_navio2")
	target_link_libraries(px4 PRIVATE atomic)

	# vscode launch.json
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Debug/launch_rpi.json.in ${PX4_SOURCE_DIR}/.vscode/launch.json COPYONLY)

elseif("${PX4_BOARD}" MATCHES "sitl")

	# vscode launch.json
	if(${PX4_BOARD_LABEL} MATCHES "replay")
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Debug/launch_replay.json.in ${PX4_SOURCE_DIR}/.vscode/launch.json COPYONLY)
	else()
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Debug/launch_sim.json.in ${PX4_SOURCE_DIR}/.vscode/launch.json COPYONLY)
	endif()

	include(sitl_target)
	if(BUILD_TESTING)
		include(sitl_tests)
	endif()

	# install

	# px4 dirs
	install(
		DIRECTORY
			${PROJECT_SOURCE_DIR}/integrationtests
			${PROJECT_SOURCE_DIR}/launch
			${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
		DESTINATION
			${PROJECT_NAME}
		USE_SOURCE_PERMISSIONS
		)

	# px4 files
	install(
		FILES
			${PROJECT_SOURCE_DIR}/CMakeLists.txt
			${PROJECT_SOURCE_DIR}/package.xml
		DESTINATION
			${PROJECT_NAME}
		)

	# px4 Tools dirs
	install(
		DIRECTORY
			${PROJECT_SOURCE_DIR}/Tools/ecl_ekf
		DESTINATION
			${PROJECT_NAME}/Tools
		USE_SOURCE_PERMISSIONS
		)

	# px4 Tools files
	install(
		PROGRAMS
			${PROJECT_SOURCE_DIR}/Tools/setup_gazebo.bash
			${PROJECT_SOURCE_DIR}/Tools/upload_log.py
		DESTINATION
			${PROJECT_NAME}/Tools
		)

	# ROMFS files
	install(
		DIRECTORY
			${PX4_BINARY_DIR}/etc
		DESTINATION
			${PROJECT_NAME}/build/px4_sitl_default
		)

	# sitl_gazebo built plugins
	install(
		DIRECTORY
			${PX4_BINARY_DIR}/build_gazebo
		DESTINATION
			${PROJECT_NAME}/build/px4_sitl_default
		FILES_MATCHING
			PATTERN "CMakeFiles" EXCLUDE
			PATTERN "*.so"
		)

	# sitl_gazebo dirs
	install(
		DIRECTORY
			${PROJECT_SOURCE_DIR}/Tools/sitl_gazebo/models
			${PROJECT_SOURCE_DIR}/Tools/sitl_gazebo/worlds
		DESTINATION
			${PROJECT_NAME}/Tools/sitl_gazebo
		)

	# sitl_gazebo files
	install(
		FILES
			${PROJECT_SOURCE_DIR}/Tools/sitl_gazebo/CMakeLists.txt
			${PROJECT_SOURCE_DIR}/Tools/sitl_gazebo/package.xml
		DESTINATION
			${PROJECT_NAME}/Tools/sitl_gazebo
		)

endif()
