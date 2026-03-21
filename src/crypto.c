#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(crypto, LOG_LEVEL_INF);

#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <zephyr/timing/timing.h>

#include <wolfssl/ssl.h>
#include <wolfcrypt/error-crypt.h>
#include <wolfcrypt/types.h>
#include <wolfcrypt/aes.h>
#include <wolfcrypt/sha256.h>

#include "crypto.h"

static int aes128_cbc_process(struct crypto_context *ctx, int enc, struct Aes *aes, uint8_t *in,
			      size_t len, uint8_t *out)
{
	int ret, ret_free;

	struct cipher_ctx cctx = {
		.keylen = aes->keylen,
		.key.bit_stream = (const uint8_t *)aes->devKey,
		.flags = ctx->crypto_aes_caps,
	};

	enum cipher_op op = enc ? CRYPTO_CIPHER_OP_ENCRYPT : CRYPTO_CIPHER_OP_DECRYPT;
	ret = cipher_begin_session(ctx->crypto_aes, &cctx, CRYPTO_CIPHER_ALGO_AES,
				   CRYPTO_CIPHER_MODE_CBC, op);
	if (ret != 0) {
		LOG_ERR("Cannot begin crypto session (%d)", ret);
		return WC_HW_E;
	}

	struct cipher_pkt cpkt = {
		.in_buf = in,
		.in_len = len,
		.out_buf = out,
		.out_buf_max = len,
	};
	LOG_DBG("%s %zu", enc ? "Encrypt" : "Decrypt", len);
	ret = cipher_cbc_op(&cctx, &cpkt, (uint8_t *)aes->reg);
	if (ret != 0) {
		LOG_ERR("Encryption failed (%d)", ret);
		ret = WC_HW_E;
		goto exit;
	}
	if ((size_t)cpkt.out_len != len) {
		LOG_ERR("Encryption failed: out len %d", cpkt.out_len);
		ret = WC_HW_E;
		goto exit;
	}

	memcpy(aes->reg, out + len - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);

exit:
	ret_free = cipher_free_session(ctx->crypto_aes, &cctx);
	if (ret_free != 0) {
		LOG_ERR("Cannot free crypto session (%d)", ret_free);
	}

	return ret;
}

static int aes_ccm_process(struct crypto_context *ctx, const Aes *aes, int encrypt, byte *out,
			   const byte *in, word32 sz, const byte *nonce, word32 nonce_sz,
			   byte *auth_tag, word32 auth_tag_sz, const byte *auth_in,
			   word32 auth_in_sz)
{
	struct cipher_pkt data_pkt = {0};
	struct cipher_aead_pkt aead_pkt = {0};
	int ret;

	if (!aes || !out || !nonce || !auth_tag) {
		return BAD_FUNC_ARG;
	}

	if (sz > 0 && in == NULL) {
		return BAD_FUNC_ARG;
	}

	if (auth_in_sz > 0 && auth_in == NULL) {
		return BAD_FUNC_ARG;
	}

	if (nonce_sz < 7 || nonce_sz > 13) {
		return BAD_FUNC_ARG;
	}

	if (auth_tag_sz != 8) {
		return BAD_FUNC_ARG;
	}

	struct cipher_ctx cctx = {
		.keylen = aes->keylen,
		.key.bit_stream = (const uint8_t *)aes->devKey,
		.mode_params.ccm_info.nonce_len = (uint16_t)nonce_sz,
		.mode_params.ccm_info.tag_len = (uint16_t)auth_tag_sz,
		.flags = CAP_RAW_KEY | CAP_SYNC_OPS | CAP_SEPARATE_IO_BUFS,
	};

	data_pkt.in_buf = (uint8_t *)in;
	data_pkt.in_len = (int)sz;
	data_pkt.out_buf = out;
	data_pkt.out_buf_max = (int)sz;

	aead_pkt.pkt = &data_pkt;
	aead_pkt.ad = (uint8_t *)auth_in;
	aead_pkt.ad_len = auth_in_sz;
	aead_pkt.tag = auth_tag;

	ret = cipher_begin_session(ctx->crypto_aes, &cctx, CRYPTO_CIPHER_ALGO_AES,
				   CRYPTO_CIPHER_MODE_CCM,
				   encrypt ? CRYPTO_CIPHER_OP_ENCRYPT : CRYPTO_CIPHER_OP_DECRYPT);
	if (ret != 0) {
		return WC_HW_E;
	}

	ret = cipher_ccm_op(&cctx, &aead_pkt, (uint8_t *)nonce);
	cipher_free_session(ctx->crypto_aes, &cctx);

	if (ret != 0) {
		if (!encrypt && ret == -EINVAL) {
			return AES_CCM_AUTH_E;
		}
		return WC_HW_E;
	}

	return 0;
}

int aes128_ccm_encrypt(struct crypto_context *ctx, const wc_CryptoCb_AesAuthEnc *op)
{
        if (op == NULL || ctx == NULL) {
                return BAD_FUNC_ARG;
        }

        return aes_ccm_process(ctx, op->aes, 1, op->out, op->in, op->sz,
                                 op->nonce, op->nonceSz, op->authTag, op->authTagSz,
                                 op->authIn, op->authInSz);
}

int aes128_ccm_decrypt(struct crypto_context *ctx, const wc_CryptoCb_AesAuthDec *op)
{
        if (op == NULL || ctx == NULL) {
                return BAD_FUNC_ARG;
        }

        return aes_ccm_process(ctx, op->aes, 0, op->out, op->in, op->sz,
                                 op->nonce, op->nonceSz, (byte *)op->authTag, op->authTagSz,
                                 op->authIn, op->authInSz);
}

static void sha256_free_ctx(struct crypto_context *ctx, struct wc_Sha256 *wctx)
{
	if (!wctx->devCtx) {
		LOG_DBG("Free NULL");
		return;
	}
	int ret = hash_free_session(ctx->crypto_sha, wctx->devCtx);
	memset(wctx->devCtx, 0, sizeof(struct hash_ctx));
	if (ret != 0) {
		LOG_ERR("Cannot free hash session (%d)", ret);
	}
	LOG_DBG("Free %p", wctx);
}

static int sha256_process(struct crypto_context *ctx, struct wc_Sha256 *wctx, const uint8_t *in, size_t size, uint8_t *out)
{
	int ret;

	struct hash_ctx *hctx = wctx->devCtx;
	if (!hctx) {
		LOG_DBG("New  %p", wctx);

		ARRAY_FOR_EACH(ctx->hctx, i) {
			if (!ctx->hctx[i].device) {
				hctx = &ctx->hctx[i];
				break;
			}
		}
		if (!hctx) {
			LOG_ERR("No more hash sessions left");
			return WC_HW_E;
		}

		hctx->flags = ctx->crypto_sha_caps;

		ret = hash_begin_session(ctx->crypto_sha, hctx, CRYPTO_HASH_ALGO_SHA256);
		if (ret != 0) {
			LOG_ERR("Cannot begin hash session (%d)", ret);
			memset(hctx, 0, sizeof(struct hash_ctx));
			return WC_HW_E;
		}

		wctx->devCtx = hctx;
	}

	if (size > 0) {
		LOG_DBG("Update %p %zu", wctx, size);
		struct hash_pkt hpkt = {
			.in_buf = in,
			.in_len = size,
			.out_buf = NULL,
		};
		ret = hash_update(hctx, &hpkt);
		if (ret != 0) {
			LOG_ERR("Cannot update hash (%d)", ret);
		}
	} else {
		LOG_DBG("Final  %p", wctx);
		struct hash_pkt hpkt = {
			.in_buf = NULL,
			.in_len = 0,
			.out_buf = out,
		};
		ret = hash_compute(hctx, &hpkt);
		if (ret != 0) {
			LOG_ERR("Cannot compute hash (%d)", ret);
		}
	}

	return ret;
}

static int wc_crypto_cb(int dev_id, struct wc_CryptoInfo *info, void *p)
{
	struct crypto_context *ctx = p;

	if (dev_id != ZEPHYR_DEVID) {
		return CRYPTOCB_UNAVAILABLE;
	}

	if (info->algo_type == WC_ALGO_TYPE_CIPHER && info->cipher.type == WC_CIPHER_AES_CBC) {
		return aes128_cbc_process(ctx, info->cipher.enc, info->cipher.aescbc.aes,
				     (uint8_t *)info->cipher.aescbc.in, info->cipher.aescbc.sz,
				     (uint8_t *)info->cipher.aescbc.out);
	}

	if (info->algo_type == WC_ALGO_TYPE_CIPHER && info->cipher.type == WC_CIPHER_AES_CCM) {
		if (info->cipher.enc) {
			return aes128_ccm_encrypt(ctx, &info->cipher.aesccm_enc);
		} else {
			return aes128_ccm_decrypt(ctx, &info->cipher.aesccm_dec);
		}
	}

	if (info->algo_type == WC_ALGO_TYPE_FREE && info->free.algo == WC_ALGO_TYPE_HASH &&
		info->free.type == WC_HASH_TYPE_SHA256) {
		wc_Sha256 *obj = info->free.obj;
		if (obj && obj->flags == WC_HASH_FLAG_NONE) {
			sha256_free_ctx(ctx, obj);
			/* We need just the fact that a context is being freed,
			 * so let wolfCrypt do its work as if cb wasn't called.  */
			return CRYPTOCB_UNAVAILABLE;
		}
	}

	if (info->algo_type == WC_ALGO_TYPE_HASH && info->hash.type == WC_HASH_TYPE_SHA256) {
		/* Don't get involved into tracking of copies
		 * (see WC_HASH_FLAG_WILLCOPY and WC_HASH_FLAG_ISCOPY).  */
		if (info->hash.sha256->flags == WC_HASH_FLAG_NONE) {
			return sha256_process(ctx, info->hash.sha256, info->hash.in,
					      info->hash.inSz, info->hash.digest);
		}
	}

	if (info->algo_type == WC_ALGO_TYPE_RNG) {
		return sys_csrand_get(info->rng.out, info->rng.sz);
	}

	return CRYPTOCB_UNAVAILABLE;
}

#ifdef CONFIG_RISCV
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/chacha.h>
#define WOLFSSL_MISC_INCLUDED
#include <wolfcrypt/src/misc.c>

/* Provided by chacha-riscv.S */
void ChaCha20_ctr32(byte *out, const byte *in, size_t len, const word32 *key,
		    const word32 *counter);

__attribute__((section(".chacha_wrap")))
int __wrap_wc_Chacha_Process(ChaCha *ctx, byte *output, const byte *input, word32 msglen)
{
	word32 full;

	if (ctx == NULL || output == NULL || input == NULL) {
		return BAD_FUNC_ARG;
	}

	if (msglen == 0) {
		return 0;
	}

	__ASSERT(((uintptr_t)input & 3) == 0, "input misaligned: %p", input);
	__ASSERT(((uintptr_t)output & 3) == 0, "output misaligned: %p", output);

	/* Process all full 64-byte blocks in one shot */
	full = msglen & ~((word32)(CHACHA_CHUNK_BYTES - 1));
	if (full > 0) {
		ChaCha20_ctr32(output, input, full, &ctx->X[4], &ctx->X[CHACHA_MATRIX_CNT_IV]);
		ctx->X[CHACHA_MATRIX_CNT_IV] += full / CHACHA_CHUNK_BYTES;
		output += full;
		input += full;
		msglen -= full;
	}

	/* Partial tail: generate one keystream block and XOR the needed bytes */
	if (msglen > 0) {
		byte zeros[CHACHA_CHUNK_BYTES];
		byte ks[CHACHA_CHUNK_BYTES];
		XMEMSET(zeros, 0, sizeof(zeros));
		ChaCha20_ctr32(ks, zeros, CHACHA_CHUNK_BYTES, &ctx->X[4],
			       &ctx->X[CHACHA_MATRIX_CNT_IV]);
		ctx->X[CHACHA_MATRIX_CNT_IV]++;
		xorbufout(output, input, ks, msglen);
	}

	return 0;
}
#endif /* CONFIG_RISCV */

void wolfssl_log(const int logLevel, const char *const logMessage)
{
	if (logLevel == ERROR_LOG) {
		LOG_ERR("%s", logMessage);
	} else if (logLevel == INFO_LOG) {
		LOG_WRN("%s", logMessage);
	} else {
		LOG_INF("%s", logMessage);
	}
}

int crypto_init(struct crypto_context *ctx)
{
	const struct device *const crypto_aes_dev = DEVICE_DT_GET_ONE(espressif_esp32_aes);
	if (!device_is_ready(crypto_aes_dev)) {
		LOG_ERR("Crypto AES device is not ready\n");
		return -EINVAL;
	}

	uint32_t required_aes_caps =
		CAP_RAW_KEY | CAP_SYNC_OPS | CAP_SEPARATE_IO_BUFS | CAP_NO_IV_PREFIX;

	uint32_t aes_caps = crypto_query_hwcaps(crypto_aes_dev);
	if ((aes_caps & required_aes_caps) != required_aes_caps) {
		return -EINVAL;
	}

	ctx->crypto_aes_caps = required_aes_caps;
	ctx->crypto_aes = crypto_aes_dev;

	const struct device *const crypto_sha_dev = DEVICE_DT_GET_ONE(espressif_esp32_sha);
	if (!device_is_ready(crypto_sha_dev)) {
		LOG_ERR("Crypto SHA device is not ready\n");
		return -EINVAL;
	}

	uint32_t required_sha_caps = CAP_SEPARATE_IO_BUFS | CAP_SYNC_OPS;

	uint32_t sha_caps = crypto_query_hwcaps(crypto_sha_dev);
	if ((sha_caps & required_sha_caps) != required_sha_caps) {
		return -EINVAL;
	}

	ctx->crypto_sha_caps = required_sha_caps;
	ctx->crypto_sha = crypto_sha_dev;

	if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
		LOG_ERR("Cannot initialize wolfSSL");
		return -EINVAL;
	}

	LOG_INF("wolfSSL %s", wolfSSL_lib_version());

	/* Set CONFIG_WOLFSSL_DEBUG=y in prj.conf to turn on debug logging. */
	wolfSSL_Debugging_ON();
	wolfSSL_SetLoggingCb(wolfssl_log);

#ifdef WOLFSSL_TRACK_MEMORY
	InitMemoryTracker();
#endif

	memset(ctx->hctx, 0, sizeof(ctx->hctx));

	int ret = wc_CryptoCb_RegisterDevice(ZEPHYR_DEVID, wc_crypto_cb, ctx);
	if (ret != 0) {
		wolfSSL_Cleanup();
		return -EINVAL;
	}

	LOG_INF("Registered crypto device %d", ZEPHYR_DEVID);

	return 0;
}
