#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <zephyr/device.h>
#include <zephyr/crypto/crypto.h>

#include <wolfssl/wolfcrypt/cryptocb.h>

#define ZEPHYR_DEVID 0

struct crypto_context {
#ifndef NO_AES
	const struct device *crypto_aes;
	uint32_t crypto_aes_caps;
#endif
#ifndef NO_SHA256
	const struct device *crypto_sha;
	uint32_t crypto_sha_caps;

	struct hash_ctx hctx[CONFIG_CRYPTO_ESP32_SHA_SESSIONS_MAX];

	size_t sha_bytes_processed;
	size_t sha_bytes_fallback;
#endif
};

int crypto_init(struct crypto_context *ctx);

#endif
