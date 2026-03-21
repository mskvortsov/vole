#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(bench, LOG_LEVEL_INF);

#include <zephyr/sys/clock.h>
#include <zephyr/timing/timing.h>
#include <zephyr/sys/util.h>
#include <zephyr/logging/log_ctrl.h>

#include <wolfcrypt/aes.h>
#include <wolfcrypt/sha256.h>
#include <wolfcrypt/chacha20_poly1305.h>

#if defined(CONFIG_VOLE_BENCH)

#include "crypto.h"

static uint8_t *bench_make_input(size_t size)
{
	uint8_t *data = k_malloc(size);
	if (!data) {
		LOG_ERR("crypto bench allocation failed");
		return NULL;
	}
	for (size_t i = 0; i < size; ++i) {
		data[i] = (' ' + i) % 95;
	}
	return data;
}

static const uint8_t bench_key[16] = {
	0x6f, 0xa1, 0x34, 0x6a, 0x46, 0x12, 0x6c, 0x2a,
	0xbf, 0x8b, 0x4e, 0x00, 0x85, 0x7b, 0x57, 0xfe
};
static const uint8_t bench_iv[16] = {
	0xad, 0x32, 0x01, 0x47, 0x44, 0x26, 0x86, 0xa3,
	0x6f, 0x67, 0xc3, 0x31, 0x30, 0x68, 0xd2, 0x38
};

static inline int bench_aes_cbc(Aes *aes, int dir, uint8_t *out, const uint8_t *inp, size_t size)
{
	if (dir == AES_ENCRYPTION) {
		return wc_AesCbcEncrypt(aes, out, inp, size);
	} else {
		return wc_AesCbcDecrypt(aes, out, inp, size);
	}
}

static void bench_aes(int dev_id)
{
	const int rounds = 50;
	const size_t sizes[3] = { 128, 640, 1280 };
	const int dirs[2] = { AES_ENCRYPTION, AES_DECRYPTION };
	uint8_t *out = k_malloc(1280);
	if (!out) {
		LOG_ERR("crypto bench allocation failed");
		return;
	}

	LOG_INF("running aes128-cbc %s, %d rounds", dev_id == ZEPHYR_DEVID ? "hw" : "sw", rounds);
	log_flush();

	timing_start();

	ARRAY_FOR_EACH(dirs, k) {
		int dir = dirs[k];
		ARRAY_FOR_EACH(sizes, j) {
			size_t size = sizes[j];
			uint8_t *inp = bench_make_input(size);

			Aes aes;
			wc_AesInit(&aes, NULL, dev_id);
			wc_AesSetKey(&aes, bench_key, sizeof(bench_key), bench_iv, dir);

			timing_t start = timing_counter_get();
			for (int i = 0; i < rounds; ++i) {
				bench_aes_cbc(&aes, dir, out, inp, size);
			}
			timing_t end = timing_counter_get();

			uint64_t ns = timing_cycles_to_ns(timing_cycles_get(&start, &end));
			uint64_t avg_ns = ns / rounds;
			uint32_t kbps = (uint64_t)size * 8 * NSEC_PER_SEC / (avg_ns * 1000);

			LOG_INF("%s @ %4zu bytes -- %5u Kb/s avg",
				dir == AES_ENCRYPTION ? "encrypt" : "decrypt", size, kbps);

			k_free(inp);
		}
	}

	timing_stop();
	k_free(out);
}

static void bench_sha(int dev_id)
{
	const int rounds = 200;
	const int sizes[3] = { 128, 640, 1280 };
	uint8_t hash[32];

	LOG_INF("running sha256 %s, %d rounds", dev_id == ZEPHYR_DEVID ? "hw" : "sw", rounds);
	log_flush();

	timing_start();

	ARRAY_FOR_EACH(sizes, j) {
		size_t size = sizes[j];
		uint8_t *inp = bench_make_input(size);

		Sha256 sha;
		wc_InitSha256_ex(&sha, NULL, dev_id);

		timing_t start = timing_counter_get();
		for (int i = 0; i < rounds; ++i) {
			wc_Sha256Update(&sha, inp, size);
			wc_Sha256Final(&sha, hash);
		}
		timing_t end = timing_counter_get();

		uint64_t ns = timing_cycles_to_ns(timing_cycles_get(&start, &end));
		uint64_t avg_ns = ns / rounds;
		uint32_t kbps = (uint64_t)size * 8 * NSEC_PER_SEC / (avg_ns * 1000);

		LOG_INF("hashing @ %4zu bytes -- %5u Kb/s avg", size, kbps);

		k_free(inp);
	}
	timing_stop();
}

static void bench_chacha20_poly1305(void)
{
	static const uint8_t key[CHACHA20_POLY1305_AEAD_KEYSIZE] = {
		0x3d, 0x7a, 0xe9, 0x86, 0x75, 0x89, 0x97, 0xf6,
		0xa6, 0x32, 0xc7, 0x02, 0xeb, 0x8e, 0x18, 0xfe,
		0xa1, 0xc3, 0x88, 0xfa, 0xcf, 0x7e, 0x03, 0xe9,
		0xda, 0xfc, 0xcc, 0x38, 0x2c, 0x37, 0xbb, 0xb8,
	};
	static const uint8_t iv[CHACHA20_POLY1305_AEAD_IV_SIZE] = {
		0x13, 0x99, 0xd8, 0x62, 0x70, 0xf7, 0xa8, 0xbd,
		0xe3, 0x7a, 0x85, 0x0d,
	};
	static const uint8_t aad[5] = { 0x17, 0x03, 0x03, 0x01, 0x10 };
	static const uint8_t auth_tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

	const int rounds = 50;
	const int sizes[3] = { 128, 640, 1280 };
	uint8_t *out = k_malloc(1280);
	if (!out) {
		LOG_ERR("crypto bench allocation failed");
		return;
	}
	uint8_t *dec = k_malloc(1280);
	if (!dec) {
		LOG_ERR("crypto bench allocation failed");
		k_free(out);
		return;
	}

	LOG_INF("running chacha20-poly1305 sw, %d rounds", rounds);
	log_flush();

	timing_start();

	for (int dir = 0; dir < 2; ++dir) {
		ARRAY_FOR_EACH(sizes, j) {
			size_t size = sizes[j];
			uint8_t *inp = bench_make_input(size);

			timing_t start = timing_counter_get();
			for (int i = 0; i < rounds; ++i) {
				int ret;
				if (dir == 0) {
					ret = wc_ChaCha20Poly1305_Encrypt(key, iv, aad, sizeof(aad),
									  inp, size, out, auth_tag);
				} else {
					ret = wc_ChaCha20Poly1305_Decrypt(key, iv, aad, sizeof(aad),
									  out, size, auth_tag, dec);
				}
				ARG_UNUSED(ret);
			}
			timing_t end = timing_counter_get();

			uint64_t ns = timing_cycles_to_ns(timing_cycles_get(&start, &end));
			uint64_t avg_ns = ns / rounds;
			uint32_t kbps = (uint64_t)size * 8 * NSEC_PER_SEC / (avg_ns * 1000);

			LOG_INF("%s @ %4zu bytes -- %5u Kb/s avg",
				dir == 0 ? "encrypt" : "decrypt", size, kbps);

			k_free(inp);
		}
	}

	timing_stop();
	k_free(dec);
	k_free(out);
}

void bench()
{
	timing_init();
	bench_aes(INVALID_DEVID);
	bench_aes(ZEPHYR_DEVID);
	bench_sha(INVALID_DEVID);
	bench_sha(ZEPHYR_DEVID);
	bench_chacha20_poly1305();
}

#else

void bench()
{
}

#endif /* CONFIG_VOLE_BENCH */
