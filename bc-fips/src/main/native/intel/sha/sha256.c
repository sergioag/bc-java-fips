//
//

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "sha256.h"
#include "../util/util.h"

void hashBlock(sha256_ctx *ctx, uint8_t *block);


static const uint8_t padBlock[64] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static inline int processLength(sha256_ctx *ctx, size_t length) {
    ctx->buf[63] = (uint8_t) (length & 0xFF);
    ctx->buf[62] = (uint8_t) ((length >> 8) & 0xFF);
    ctx->buf[61] = (uint8_t) ((length >> 16) & 0xFF);
    ctx->buf[60] = (uint8_t) ((length >> 24) & 0xFF);
    ctx->buf[59] = (uint8_t) ((length >> 32) & 0xFF);
    ctx->buf[58] = (uint8_t) ((length >> 40) & 0xFF);
    ctx->buf[57] = (uint8_t) ((length >> 48) & 0xFF);
    ctx->buf[56] = (uint8_t) ((length >> 56) & 0xFF);
    return 8;
}

sha256_ctx *sha256_create_ctx() {
    sha256_ctx *ptr = calloc(1, sizeof(sha256_ctx));
    assert(ptr != NULL);
    sha256_reset(ptr);
    return ptr;
}

void sha256_free_ctx(sha256_ctx *ctx) {
    memzero(ctx,  sizeof(sha256_ctx));
    free(ctx);
}

void sha256_reset(sha256_ctx *ctx) {

    memset(ctx->buf, 0, BUF_SIZE_SHA256);
    ctx->ident = SHA256_MAGIC;
    ctx->buf_index = 0;
    ctx->byteCount = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;

    __m128i tmp = _mm_loadu_si128((const __m128i *) &ctx->state[0]);
    ctx->s1 = _mm_loadu_si128((const __m128i *) &ctx->state[4]);

    tmp = _mm_shuffle_epi32(tmp, 0xB1);          /* CDAB */
    ctx->s1 = _mm_shuffle_epi32(ctx->s1, 0x1B);    /* EFGH */
    ctx->s0 = _mm_alignr_epi8(tmp, ctx->s1, 8);    /* ABEF */
    ctx->s1 = _mm_blend_epi16(ctx->s1, tmp, 0xF0); /* CDGH */
}

void sha256_update(sha256_ctx *ctx, uint8_t *input, size_t len) {
    if (input == NULL || len == 0) {
        return;
    }

    uint8_t *end = input + len;

    if (ctx->buf_index != 0) {
        size_t rem = BUF_SIZE_SHA256 - ctx->buf_index;
        size_t toCopy = len < rem ? len : rem;
        memcpy(&ctx->buf[ctx->buf_index], input, toCopy);
        ctx->buf_index += toCopy;
        input += toCopy;
        ctx->byteCount += toCopy;

        if (ctx->buf_index == BUF_SIZE_SHA256) {
            hashBlock(ctx, ctx->buf);
            ctx->buf_index = 0;
        }
    }

    //
    // Directly process block
    //
    uint8_t *ptr = input;
    while (end - ptr >= BUF_SIZE_SHA256) {
        hashBlock(ctx, ptr);
        ptr += BUF_SIZE_SHA256;
        ctx->byteCount += BUF_SIZE_SHA256;
    }

    //
    // Copy in any trailing bytes that do not fill a block.
    //
    if (end - ptr > 0) {
        size_t rem = BUF_SIZE_SHA256 - ctx->buf_index;
        size_t toCopy = end - ptr < rem ? (size_t) (end - ptr) : rem;
        memcpy(&ctx->buf[ctx->buf_index], ptr, toCopy);
        ctx->buf_index += toCopy;
        ctx->byteCount += toCopy;
    }


}

void sha256_update_byte(sha256_ctx *ctx, uint8_t b) {
    ctx->buf[ctx->buf_index++] = b;
    ctx->byteCount++;
    if (ctx->buf_index == BUF_SIZE_SHA256) {
        hashBlock(ctx, (uint8_t *) &ctx->buf);
        ctx->buf_index = 0;
    }
}

void sha256_digest(sha256_ctx *ctx, uint8_t *output) {
    size_t bitLen = ctx->byteCount << 3;
    size_t padLen = ctx->buf_index < 56 ? 56 - ctx->buf_index : 64 + 56 - ctx->buf_index;
    sha256_update(ctx, (uint8_t *) padBlock, padLen);
    processLength(ctx, bitLen);
    hashBlock(ctx, ctx->buf);


    __m128i tmp = _mm_shuffle_epi32(ctx->s0, 0x1B);       /* FEBA */
    ctx->s1 = _mm_shuffle_epi32(ctx->s1, 0xB1);    /* DCHG */
    ctx->s0 = _mm_blend_epi16(tmp, ctx->s1, 0xF0); /* DCBA */
    ctx->s1 = _mm_alignr_epi8(ctx->s1, tmp, 8);    /* ABEF */

    //
    // Save state
    //
    _mm_storeu_si128((__m128i *) &ctx->state[0], ctx->s0);
    _mm_storeu_si128((__m128i *) &ctx->state[4], ctx->s1);


    _mm_storeu_si128((__m128i *) output, _mm_shuffle_epi8(ctx->s0, *SWAP_ENDIAN_SHA_256));
    _mm_storeu_si128((__m128i *) (output + 16), _mm_shuffle_epi8(ctx->s1, *SWAP_ENDIAN_SHA_256));

    sha256_reset(ctx);
}

uint32_t sha256_getSize(sha256_ctx *ctx) {
    return SHA256_SIZE;
}

uint32_t sha256_getByteLen(sha256_ctx *ctx) {
    return BUF_SIZE_SHA256;
}

bool sha256_restoreFullState(sha256_ctx *ctx, const uint8_t *oldState) {

    sha256_ctx newState;
    memcpy(&newState, oldState, sizeof(sha256_ctx));

    if (newState.ident != SHA256_MAGIC) {
        return false;
    }

    if (newState.buf_index >= BUF_SIZE_SHA256) {
        return false;
    }

    *ctx = newState;

    return true;
}

size_t sha256_encodeFullState(const sha256_ctx *ctx, uint8_t *output) {
    memcpy(output, ctx, sizeof(sha256_ctx));
    return sizeof(sha256_ctx);
}


void hashBlock(sha256_ctx *ctx, uint8_t *block) {
    //
    // Adapted on code from Intel and Jeffrey Walton
    //

    const __m128i mask = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    __m128i abef_save = ctx->s0;
    __m128i cdgh_save = ctx->s1;

    __m128i msg;
    __m128i msgTmp0;
    __m128i msg1;
    __m128i msg2;
    __m128i msg3;
    __m128i tmp;


    msg = _mm_loadu_si128((const __m128i *) (block));
    msgTmp0 = _mm_shuffle_epi8(msg, mask);
    msg = _mm_add_epi32(msgTmp0, _mm_set_epi64x(-1606136187322303537, 8158064640682241944));
    ctx->s1 = _mm_sha256rnds2_epu32(ctx->s1, ctx->s0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    ctx->s0 = _mm_sha256rnds2_epu32(ctx->s0, ctx->s1, msg);

    block += 16;


    msg1 = _mm_loadu_si128((const __m128i *) (block));
    msg1 = _mm_shuffle_epi8(msg1, mask);
    msg = _mm_add_epi32(msg1, _mm_set_epi64x(-6116909922501295452, 6480981066509632091));
    ctx->s1 = _mm_sha256rnds2_epu32(ctx->s1, ctx->s0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    ctx->s0 = _mm_sha256rnds2_epu32(ctx->s0, ctx->s1, msg);
    msgTmp0 = _mm_sha256msg1_epu32(msgTmp0, msg1);

    block += 16;


    msg2 = _mm_loadu_si128((const __m128i *) (block));
    msg2 = _mm_shuffle_epi8(msg2, mask);
    msg = _mm_add_epi32(msg2, _mm_set_epi64x(6128411470023722430, 1334009978109274776));
    ctx->s1 = _mm_sha256rnds2_epu32(ctx->s1, ctx->s0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    ctx->s0 = _mm_sha256rnds2_epu32(ctx->s0, ctx->s1, msg);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    block += 16;


    msg3 = _mm_loadu_si128((const __m128i *) (block));
    msg3 = _mm_shuffle_epi8(msg3, mask);
    msg = _mm_add_epi32(msg3, _mm_set_epi64x(-4495734319865919833, -9160688885620122252));
    ctx->s1 = _mm_sha256rnds2_epu32(ctx->s1, ctx->s0, msg);
    tmp = _mm_alignr_epi8(msg3, msg2, 4);
    msgTmp0 = _mm_add_epi32(msgTmp0, tmp);
    msgTmp0 = _mm_sha256msg2_epu32(msgTmp0, msg3);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    ctx->s0 = _mm_sha256rnds2_epu32(ctx->s0, ctx->s1, msg);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    msg = _mm_add_epi32(msgTmp0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, -1171420208383170111));
    ctx->s1 = _mm_sha256rnds2_epu32(ctx->s1, ctx->s0, msg);
    tmp = _mm_alignr_epi8(msgTmp0, msg3, 4);
    msg1 = _mm_add_epi32(msg1, tmp);
    msg1 = _mm_sha256msg2_epu32(msg1, msgTmp0);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    ctx->s0 = _mm_sha256rnds2_epu32(ctx->s0, ctx->s1, msg);
    msg3 = _mm_sha256msg1_epu32(msg3, msgTmp0);

    msg = _mm_add_epi32(msg1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 5365058922554666095));
    ctx->s1 = _mm_sha256rnds2_epu32(ctx->s1, ctx->s0, msg);
    tmp = _mm_alignr_epi8(msg1, msgTmp0, 4);
    msg2 = _mm_add_epi32(msg2, tmp);
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    ctx->s0 = _mm_sha256rnds2_epu32(ctx->s0, ctx->s1, msg);
    msgTmp0 = _mm_sha256msg1_epu32(msgTmp0, msg1);

    msg = _mm_add_epi32(msg2, _mm_set_epi64x(-4658551843909851192, -6327057827470880430));
    ctx->s1 = _mm_sha256rnds2_epu32(ctx->s1, ctx->s0, msg);
    tmp = _mm_alignr_epi8(msg2, msg1, 4);
    msg3 = _mm_add_epi32(msg3, tmp);
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    ctx->s0 = _mm_sha256rnds2_epu32(ctx->s0, ctx->s1, msg);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    msg = _mm_add_epi32(msg3, _mm_set_epi64x(0x1429296706CA6351ULL, -3051310485054944269));
    ctx->s1 = _mm_sha256rnds2_epu32(ctx->s1, ctx->s0, msg);
    tmp = _mm_alignr_epi8(msg3, msg2, 4);
    msgTmp0 = _mm_add_epi32(msgTmp0, tmp);
    msgTmp0 = _mm_sha256msg2_epu32(msgTmp0, msg3);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    ctx->s0 = _mm_sha256rnds2_epu32(ctx->s0, ctx->s1, msg);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    msg = _mm_add_epi32(msgTmp0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 3322285675184065157));
    ctx->s1 = _mm_sha256rnds2_epu32(ctx->s1, ctx->s0, msg);
    tmp = _mm_alignr_epi8(msgTmp0, msg3, 4);
    msg1 = _mm_add_epi32(msg1, tmp);
    msg1 = _mm_sha256msg2_epu32(msg1, msgTmp0);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    ctx->s0 = _mm_sha256rnds2_epu32(ctx->s0, ctx->s1, msg);
    msg3 = _mm_sha256msg1_epu32(msg3, msgTmp0);

    msg = _mm_add_epi32(msg1, _mm_set_epi64x(-7894198244907759314, 8532644243977171796));
    ctx->s1 = _mm_sha256rnds2_epu32(ctx->s1, ctx->s0, msg);
    tmp = _mm_alignr_epi8(msg1, msgTmp0, 4);
    msg2 = _mm_add_epi32(msg2, tmp);
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    ctx->s0 = _mm_sha256rnds2_epu32(ctx->s0, ctx->s1, msg);
    msgTmp0 = _mm_sha256msg1_epu32(msgTmp0, msg1);

    msg = _mm_add_epi32(msg2, _mm_set_epi64x(-4076793798895891600, -6333637450904115039));
    ctx->s1 = _mm_sha256rnds2_epu32(ctx->s1, ctx->s0, msg);
    tmp = _mm_alignr_epi8(msg2, msg1, 4);
    msg3 = _mm_add_epi32(msg3, tmp);
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    ctx->s0 = _mm_sha256rnds2_epu32(ctx->s0, ctx->s1, msg);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    msg = _mm_add_epi32(msg3, _mm_set_epi64x(0x106AA070F40E3585ULL, -2983346522951587815));
    ctx->s1 = _mm_sha256rnds2_epu32(ctx->s1, ctx->s0, msg);
    tmp = _mm_alignr_epi8(msg3, msg2, 4);
    msgTmp0 = _mm_add_epi32(msgTmp0, tmp);
    msgTmp0 = _mm_sha256msg2_epu32(msgTmp0, msg3);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    ctx->s0 = _mm_sha256rnds2_epu32(ctx->s0, ctx->s1, msg);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    msg = _mm_add_epi32(msgTmp0, _mm_set_epi64x(0x34B0BCB52748774CULL, 2177327726902690070));
    ctx->s1 = _mm_sha256rnds2_epu32(ctx->s1, ctx->s0, msg);
    tmp = _mm_alignr_epi8(msgTmp0, msg3, 4);
    msg1 = _mm_add_epi32(msg1, tmp);
    msg1 = _mm_sha256msg2_epu32(msg1, msgTmp0);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    ctx->s0 = _mm_sha256rnds2_epu32(ctx->s0, ctx->s1, msg);
    msg3 = _mm_sha256msg1_epu32(msg3, msgTmp0);

    msg = _mm_add_epi32(msg1, _mm_set_epi64x(7507060719877933647, 5681478165690322099));
    ctx->s1 = _mm_sha256rnds2_epu32(ctx->s1, ctx->s0, msg);
    tmp = _mm_alignr_epi8(msg1, msgTmp0, 4);
    msg2 = _mm_add_epi32(msg2, tmp);
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    ctx->s0 = _mm_sha256rnds2_epu32(ctx->s0, ctx->s1, msg);

    msg = _mm_add_epi32(msg2, _mm_set_epi64x(-8302665152423495660, 8693463986056692462));
    ctx->s1 = _mm_sha256rnds2_epu32(ctx->s1, ctx->s0, msg);
    tmp = _mm_alignr_epi8(msg2, msg1, 4);
    msg3 = _mm_add_epi32(msg3, tmp);
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    ctx->s0 = _mm_sha256rnds2_epu32(ctx->s0, ctx->s1, msg);

    msg = _mm_add_epi32(msg3, _mm_set_epi64x(-4147400797850065929, -6606660894350966790));
    ctx->s1 = _mm_sha256rnds2_epu32(ctx->s1, ctx->s0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    ctx->s0 = _mm_sha256rnds2_epu32(ctx->s0, ctx->s1, msg);

    ctx->s0 = _mm_add_epi32(ctx->s0, abef_save);
    ctx->s1 = _mm_add_epi32(ctx->s1, cdgh_save);
}