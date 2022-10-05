/****************************************************************************
 *
 *   Copyright (C) 2022 PX4 Development Team. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name PX4 nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

/**
 * This is an alternative main entrypoint for fuzz testing.
 */

#include <stdint.h>

#include "px4_platform_common/init.h"
#include "px4_platform_common/posix.h"
#include "px4_platform_common/crypto.h"
#include "apps.h"
#include "px4_daemon/client.h"
#include "px4_daemon/server.h"
#include "px4_daemon/pxh.h"
#include "fuzz.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include "common/mavlink.h"

#define MODULE_NAME "px4"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

char fuzzing_buffer[4096];

namespace px4
{
void init_once();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, const size_t size);
void initialize_fake_px4_once();

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, const size_t size)
{
	//initialize_fake_px4_once();

	// Get the generated key, encrypted with RSA_OAEP. Open another temporary session for this.
	PX4Crypto rsa_crypto;

	if (!rsa_crypto.open(CRYPTO_RSA_OAEP)) {
		return false;
	}

	/* Get the size of an encrypted key and nonce */
	size_t key_size;
	rsa_crypto.get_encrypted_key(0, NULL, &key_size, 0);
	return 0;
}
/*
void initialize_fake_px4_once()
{
	static bool first_time = true;

	if (!first_time) {
		return;
	}

	first_time = false;

	px4::init_once();
	px4::init(0, nullptr, "px4");
	px4_daemon::Pxh pxh;
	pxh.process_line("uorb start", true);
	PX4_WARN("start mavlink now.");    
        pxh.process_line("mavlink start -x -o 14540 -r 4000000", true);
        pxh.process_line("mavlink boot_complete", true);
}

*/
