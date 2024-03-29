/****************************************************************************
 *
 *   Copyright (c) 2021 Technology Innovation Institute. All rights reserved.
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

#if defined(PX4_CRYPTO)

#include <px4_platform_common/crypto.h>
#include <px4_platform_common/crypto_backend.h>

//extern "C" {
//#include <nuttx/random.h>
//}


px4_sem_t PX4Crypto::_lock;
bool PX4Crypto::_initialized = false;

void PX4Crypto::px4_crypto_init()
{
	if (PX4Crypto::_initialized) {
		return;
	}

	px4_sem_init(&PX4Crypto::_lock, 0, 1);

	// Initialize nuttx random pool, if it is being used by crypto
//#ifdef CONFIG_CRYPTO_RANDOM_POOL
//	up_randompool_initialize();
//#endif

	// initialize keystore functionality
	keystore_init();

	// initialize actual crypto algoritms
	crypto_init();

	PX4Crypto::_initialized = true;
}

PX4Crypto::PX4Crypto()
{
	// Initialize an empty handle
	crypto_session_handle_init(&_crypto_handle);
}

PX4Crypto::~PX4Crypto()
{
	close();
}

bool PX4Crypto::open(px4_crypto_algorithm_t algorithm)
{
	bool ret = false;
	//lock();

	// HW specific crypto already open? Just close before proceeding
	if (crypto_session_handle_valid(_crypto_handle)) {
		crypto_close(&_crypto_handle);
	}

	// Open the HW specific crypto handle
	_crypto_handle = crypto_open(algorithm);

	if (crypto_session_handle_valid(_crypto_handle)) {
		ret = true;
	}

	//unlock();

	return ret;
}

void PX4Crypto::close()
{
	if (!crypto_session_handle_valid(_crypto_handle)) {
		return;
	}

	lock();
	crypto_close(&_crypto_handle);
	unlock();
}

bool PX4Crypto::encrypt_data(uint8_t  key_index,
			     const uint8_t *message,
			     size_t message_size,
			     uint8_t *cipher,
			     size_t *cipher_size)
{
	return false; //crypto_encrypt_data(_crypto_handle, key_index, message, message_size, cipher, cipher_size);
}

bool  PX4Crypto::generate_key(uint8_t idx,
			      bool persistent)
{
	return false; //crypto_generate_key(_crypto_handle, idx, persistent);
}


bool  PX4Crypto::get_nonce(uint8_t *nonce,
			   size_t *nonce_len)
{
	return false; //crypto_get_nonce(_crypto_handle, nonce, nonce_len);
}


bool  PX4Crypto::get_encrypted_key(uint8_t key_idx,
				   uint8_t *key,
				   size_t *key_len,
				   uint8_t encryption_key_idx)
{
	return crypto_get_encrypted_key(_crypto_handle, key_idx, key, key_len, encryption_key_idx);
}

size_t PX4Crypto::get_min_blocksize(uint8_t key_idx)
{
	return crypto_get_min_blocksize(_crypto_handle, key_idx);
}

#endif

