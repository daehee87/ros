/****************************************************************************
 *
 *   Copyright (c) 2020 Technology Innovation Institute. All rights reserved.
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
 * @file crypto.c
 *
 * Wrapper for the monocypher crypto
 *
 */

#include <inttypes.h>
#include <stdbool.h>

#include <px4_platform_common/crypto_backend.h>
#include <px4_random.h>
#include <lib/crypto/monocypher/src/optional/monocypher-ed25519.h>
#include <tomcrypt.h>

extern void libtomcrypt_init(void);

/* room for 16 keys */
#define KEY_CACHE_LEN 16

#ifndef SECMEM_ALLOC
#define SECMEM_ALLOC XMALLOC
#endif

#ifndef SECMEM_FREE
#define SECMEM_FREE XFREE
#endif

/*
 * For now, this is just a dummy up/down counter for tracking open/close calls
 */
static int crypto_open_count = 0;

/*
 * Status of libtomcrypt initialization. This is a large library, which
 * is initialized & pulled in by linker only when it is actually used
 */
static bool tomcrypt_initialized = false;

typedef struct {
	size_t key_size;
	uint8_t *key;
} volatile_key_t;

static volatile_key_t key_cache[KEY_CACHE_LEN];

typedef struct {
	uint8_t nonce[24];
	uint64_t ctr;
} chacha20_context_t;


int rsa_import(const unsigned char *in, unsigned long inlen, rsa_key *key){
	return -1234;
}
void rsa_free(rsa_key* p){
}


static inline void initialize_tomcrypt(void)
{
	if (!tomcrypt_initialized) {
		//libtomcrypt_init();
		tomcrypt_initialized = true;
	}
}

/* Clear key cache */
static void clear_key_cache(void)
{
	for (int i = 0; i < KEY_CACHE_LEN ; i++) {
		SECMEM_FREE(key_cache[i].key);
		key_cache[i].key = NULL;
		key_cache[i].key_size = 0;
	}
}

/* Retrieve a direct pointer to the cached temporary/public key */
static const uint8_t *crypto_get_key_ptr(keystore_session_handle_t handle, uint8_t key_idx,
		size_t *len)
{
	uint8_t *ret;

	if (key_idx >= KEY_CACHE_LEN) {
		*len = 0;
		return NULL;
	}

	ret = key_cache[key_idx].key;

	/* if the key doesn't exist in the key cache, try to read it in there from keystore */
	if (ret == NULL) {

		/* First check if the key exists in the keystore and retrieve its length */
		*len = keystore_get_key(handle, key_idx, NULL, 0);

		if (*len > 0) {

			/* Allocate memory for the key in the cache */
			ret = SECMEM_ALLOC(*len);

			/* Retrieve the key from the keystore */
			if (ret) {
				if (keystore_get_key(handle, key_idx, ret, *len) > 0) {
					/* Success, store the key in cache */
					key_cache[key_idx].key_size = *len;
					key_cache[key_idx].key = ret;

				} else {
					/* key retrieval failed, free the memory */
					SECMEM_FREE(ret);
				}
			}
		}
	}

	*len = key_cache[key_idx].key_size;

	return ret;
}


void crypto_init()
{
	keystore_init();
	clear_key_cache();
}

crypto_session_handle_t crypto_open(px4_crypto_algorithm_t algorithm)
{
	crypto_session_handle_t ret;
	ret.keystore_handle = keystore_open();

	if (keystore_session_handle_valid(ret.keystore_handle)) {
		ret.algorithm = algorithm;
		ret.handle = ++crypto_open_count;

	} else {
		ret.handle = 0;
		ret.context = NULL;
		ret.algorithm = CRYPTO_NONE;
		return ret;
	}

	switch (algorithm) {
	case CRYPTO_XCHACHA20: {
			chacha20_context_t *context = XMALLOC(sizeof(chacha20_context_t));

			if (!context) {
				ret.handle = 0;
				crypto_open_count--;

			} else {
				ret.context = context;
				//px4_get_secure_random(context->nonce, sizeof(context->nonce));
				context->ctr = 0;
			}
		}
		break;

	default:
		ret.context = NULL;
	}

	return ret;
}

void crypto_close(crypto_session_handle_t *handle)
{

}

bool crypto_get_encrypted_key(crypto_session_handle_t handle,
			      uint8_t key_idx,
			      uint8_t *key,
			      size_t *max_len,
			      uint8_t encryption_key_idx)
{
	// Retrieve the plaintext key
	bool ret = true;
	size_t key_sz;
	const uint8_t *plain_key = crypto_get_key_ptr(handle.keystore_handle, key_idx, &key_sz);
	if(plain_key==NULL){	
		ret = false;
	}

	if (key_sz == 0) {
		ret = false;
		//return false;
	}

	// Encrypt it
	if (key != NULL) {
		ret = false; //crypto_encrypt_data(handle,
			//		  encryption_key_idx,
			//		  plain_key,
			//		  key_sz,
			//		  key,
			//		  max_len);

	} else {
		// The key size, encrypted, is a multiple of minimum block size for the algorithm+key
		size_t min_block = crypto_get_min_blocksize(handle, encryption_key_idx);
		*max_len = key_sz / min_block * min_block;

		if (key_sz % min_block) {
			*max_len += min_block;
		}
	}

	return ret;
}


size_t crypto_get_min_blocksize(crypto_session_handle_t handle, uint8_t key_idx)
{
	size_t ret;

	switch (handle.algorithm) {
	case CRYPTO_XCHACHA20:
		ret = 64;
		break;

	case CRYPTO_RSA_OAEP: {
			rsa_key enc_key;
			size_t pub_key_sz;
			uint8_t *pub_key = (uint8_t *)crypto_get_key_ptr(handle.keystore_handle, key_idx, &pub_key_sz);

			initialize_tomcrypt();

			if (pub_key &&
			    rsa_import(pub_key, pub_key_sz, &enc_key) == CRYPT_OK) {
				ret = 1; //ltc_mp.unsigned_size(enc_key.N);
				rsa_free(&enc_key);

			} else {
				ret = 0;
			}
		}
		break;

	default:
		ret = 1;
	}

	return ret;
}

