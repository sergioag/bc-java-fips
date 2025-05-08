
#ifndef BC_FIPS_AES_CTR256_H
#define BC_FIPS_AES_CTR256_H

#include <immintrin.h>
#include <stdint.h>
#include <stdbool.h>
#include "ctr.h"

// 256 bit --

static const int8_t __attribute__ ((aligned(32))) _swap_endian_256[32] = {
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
};

static const __m256i *SWAP_ENDIAN_256 = ((__m256i *) _swap_endian_256);


static const uint32_t __attribute__ ((aligned(32))) _inc_256_ctr[8] = {
        2,0,0,0,2,0,0,0
};

static __m256i *INC_CTR_256 = (__m256i *) _inc_256_ctr;


static const uint32_t __attribute__ ((aligned(32)))  _spread_256[8] = {
        0,0,0,0,1,0,0,0
};

static __m256i *SPREAD_256 = (__m256i *) _spread_256;


static inline void
aes_ctr256_wide(__m256i *d0, __m256i *d1, __m256i *d2, __m256i *d3, __m256i *d4, __m256i *d5, __m256i *d6, __m256i *d7,
                __m128i *roundKeys, const __m128i ctr, const uint32_t max_rounds, const uint32_t blocks) {

    __m256i ctr0, ctr1, ctr2, ctr3, ctr4, ctr5, ctr6, ctr7;

    if (blocks == 16) {
        ctr0 = _mm256_add_epi64(_mm256_broadcastsi128_si256(ctr), *SPREAD_256);
        ctr1 = _mm256_add_epi64(ctr0, *INC_CTR_256);
        ctr2 = _mm256_add_epi64(ctr1, *INC_CTR_256);
        ctr3 = _mm256_add_epi64(ctr2, *INC_CTR_256);
        ctr4 = _mm256_add_epi64(ctr3, *INC_CTR_256);
        ctr5 = _mm256_add_epi64(ctr4, *INC_CTR_256);
        ctr6 = _mm256_add_epi64(ctr5, *INC_CTR_256);
        ctr7 = _mm256_add_epi64(ctr6, *INC_CTR_256);

        ctr0 = _mm256_shuffle_epi8(ctr0, *SWAP_ENDIAN_256);
        ctr1 = _mm256_shuffle_epi8(ctr1, *SWAP_ENDIAN_256);
        ctr2 = _mm256_shuffle_epi8(ctr2, *SWAP_ENDIAN_256);
        ctr3 = _mm256_shuffle_epi8(ctr3, *SWAP_ENDIAN_256);
        ctr4 = _mm256_shuffle_epi8(ctr4, *SWAP_ENDIAN_256);
        ctr5 = _mm256_shuffle_epi8(ctr5, *SWAP_ENDIAN_256);
        ctr6 = _mm256_shuffle_epi8(ctr6, *SWAP_ENDIAN_256);
        ctr7 = _mm256_shuffle_epi8(ctr7, *SWAP_ENDIAN_256);

        const __m256i rk0 = _mm256_broadcastsi128_si256(roundKeys[0]);
        ctr0 = _mm256_xor_si256(ctr0, rk0);
        ctr1 = _mm256_xor_si256(ctr1, rk0);
        ctr2 = _mm256_xor_si256(ctr2, rk0);
        ctr3 = _mm256_xor_si256(ctr3, rk0);
        ctr4 = _mm256_xor_si256(ctr4, rk0);
        ctr5 = _mm256_xor_si256(ctr5, rk0);
        ctr6 = _mm256_xor_si256(ctr6, rk0);
        ctr7 = _mm256_xor_si256(ctr7, rk0);

        int r;
        for (r = 1; r < max_rounds; r++) {
            const __m256i rk = _mm256_broadcastsi128_si256(roundKeys[r]);
            ctr0 = _mm256_aesenc_epi128(ctr0, rk);
            ctr1 = _mm256_aesenc_epi128(ctr1, rk);
            ctr2 = _mm256_aesenc_epi128(ctr2, rk);
            ctr3 = _mm256_aesenc_epi128(ctr3, rk);
            ctr4 = _mm256_aesenc_epi128(ctr4, rk);
            ctr5 = _mm256_aesenc_epi128(ctr5, rk);
            ctr6 = _mm256_aesenc_epi128(ctr6, rk);
            ctr7 = _mm256_aesenc_epi128(ctr7, rk);
        }

        const __m256i rkLast = _mm256_broadcastsi128_si256(roundKeys[r]);
        ctr0 = _mm256_aesenclast_epi128(ctr0, rkLast);
        ctr1 = _mm256_aesenclast_epi128(ctr1, rkLast);
        ctr2 = _mm256_aesenclast_epi128(ctr2, rkLast);
        ctr3 = _mm256_aesenclast_epi128(ctr3, rkLast);
        ctr4 = _mm256_aesenclast_epi128(ctr4, rkLast);
        ctr5 = _mm256_aesenclast_epi128(ctr5, rkLast);
        ctr6 = _mm256_aesenclast_epi128(ctr6, rkLast);
        ctr7 = _mm256_aesenclast_epi128(ctr7, rkLast);


        *d0 = _mm256_xor_si256(ctr0, *d0);
        *d1 = _mm256_xor_si256(ctr1, *d1);
        *d2 = _mm256_xor_si256(ctr2, *d2);
        *d3 = _mm256_xor_si256(ctr3, *d3);
        *d4 = _mm256_xor_si256(ctr4, *d4);
        *d5 = _mm256_xor_si256(ctr5, *d5);
        *d6 = _mm256_xor_si256(ctr6, *d6);
        *d7 = _mm256_xor_si256(ctr7, *d7);
    } else if (blocks == 14) {
        ctr0 = _mm256_add_epi64(_mm256_broadcastsi128_si256(ctr), *SPREAD_256);
        ctr1 = _mm256_add_epi64(ctr0, *INC_CTR_256);
        ctr2 = _mm256_add_epi64(ctr1, *INC_CTR_256);
        ctr3 = _mm256_add_epi64(ctr2, *INC_CTR_256);
        ctr4 = _mm256_add_epi64(ctr3, *INC_CTR_256);
        ctr5 = _mm256_add_epi64(ctr4, *INC_CTR_256);
        ctr6 = _mm256_add_epi64(ctr5, *INC_CTR_256);


        ctr0 = _mm256_shuffle_epi8(ctr0, *SWAP_ENDIAN_256);
        ctr1 = _mm256_shuffle_epi8(ctr1, *SWAP_ENDIAN_256);
        ctr2 = _mm256_shuffle_epi8(ctr2, *SWAP_ENDIAN_256);
        ctr3 = _mm256_shuffle_epi8(ctr3, *SWAP_ENDIAN_256);
        ctr4 = _mm256_shuffle_epi8(ctr4, *SWAP_ENDIAN_256);
        ctr5 = _mm256_shuffle_epi8(ctr5, *SWAP_ENDIAN_256);
        ctr6 = _mm256_shuffle_epi8(ctr6, *SWAP_ENDIAN_256);


        const __m256i rk0 = _mm256_broadcastsi128_si256(roundKeys[0]);
        ctr0 = _mm256_xor_si256(ctr0, rk0);
        ctr1 = _mm256_xor_si256(ctr1, rk0);
        ctr2 = _mm256_xor_si256(ctr2, rk0);
        ctr3 = _mm256_xor_si256(ctr3, rk0);
        ctr4 = _mm256_xor_si256(ctr4, rk0);
        ctr5 = _mm256_xor_si256(ctr5, rk0);
        ctr6 = _mm256_xor_si256(ctr6, rk0);


        int r;
        for (r = 1; r < max_rounds; r++) {
            const __m256i rk = _mm256_broadcastsi128_si256(roundKeys[r]);
            ctr0 = _mm256_aesenc_epi128(ctr0, rk);
            ctr1 = _mm256_aesenc_epi128(ctr1, rk);
            ctr2 = _mm256_aesenc_epi128(ctr2, rk);
            ctr3 = _mm256_aesenc_epi128(ctr3, rk);
            ctr4 = _mm256_aesenc_epi128(ctr4, rk);
            ctr5 = _mm256_aesenc_epi128(ctr5, rk);
            ctr6 = _mm256_aesenc_epi128(ctr6, rk);

        }

        const __m256i rkLast = _mm256_broadcastsi128_si256(roundKeys[r]);
        ctr0 = _mm256_aesenclast_epi128(ctr0, rkLast);
        ctr1 = _mm256_aesenclast_epi128(ctr1, rkLast);
        ctr2 = _mm256_aesenclast_epi128(ctr2, rkLast);
        ctr3 = _mm256_aesenclast_epi128(ctr3, rkLast);
        ctr4 = _mm256_aesenclast_epi128(ctr4, rkLast);
        ctr5 = _mm256_aesenclast_epi128(ctr5, rkLast);
        ctr6 = _mm256_aesenclast_epi128(ctr6, rkLast);


        *d0 = _mm256_xor_si256(ctr0, *d0);
        *d1 = _mm256_xor_si256(ctr1, *d1);
        *d2 = _mm256_xor_si256(ctr2, *d2);
        *d3 = _mm256_xor_si256(ctr3, *d3);
        *d4 = _mm256_xor_si256(ctr4, *d4);
        *d5 = _mm256_xor_si256(ctr5, *d5);
        *d6 = _mm256_xor_si256(ctr6, *d6);

    } else if (blocks == 12) {
        ctr0 = _mm256_add_epi64(_mm256_broadcastsi128_si256(ctr), *SPREAD_256);
        ctr1 = _mm256_add_epi64(ctr0, *INC_CTR_256);
        ctr2 = _mm256_add_epi64(ctr1, *INC_CTR_256);
        ctr3 = _mm256_add_epi64(ctr2, *INC_CTR_256);
        ctr4 = _mm256_add_epi64(ctr3, *INC_CTR_256);
        ctr5 = _mm256_add_epi64(ctr4, *INC_CTR_256);

        ctr0 = _mm256_shuffle_epi8(ctr0, *SWAP_ENDIAN_256);
        ctr1 = _mm256_shuffle_epi8(ctr1, *SWAP_ENDIAN_256);
        ctr2 = _mm256_shuffle_epi8(ctr2, *SWAP_ENDIAN_256);
        ctr3 = _mm256_shuffle_epi8(ctr3, *SWAP_ENDIAN_256);
        ctr4 = _mm256_shuffle_epi8(ctr4, *SWAP_ENDIAN_256);
        ctr5 = _mm256_shuffle_epi8(ctr5, *SWAP_ENDIAN_256);

        const __m256i rk0 = _mm256_broadcastsi128_si256(roundKeys[0]);
        ctr0 = _mm256_xor_si256(ctr0, rk0);
        ctr1 = _mm256_xor_si256(ctr1, rk0);
        ctr2 = _mm256_xor_si256(ctr2, rk0);
        ctr3 = _mm256_xor_si256(ctr3, rk0);
        ctr4 = _mm256_xor_si256(ctr4, rk0);
        ctr5 = _mm256_xor_si256(ctr5, rk0);

        int r;
        for (r = 1; r < max_rounds; r++) {
            const __m256i rk = _mm256_broadcastsi128_si256(roundKeys[r]);
            ctr0 = _mm256_aesenc_epi128(ctr0, rk);
            ctr1 = _mm256_aesenc_epi128(ctr1, rk);
            ctr2 = _mm256_aesenc_epi128(ctr2, rk);
            ctr3 = _mm256_aesenc_epi128(ctr3, rk);
            ctr4 = _mm256_aesenc_epi128(ctr4, rk);
            ctr5 = _mm256_aesenc_epi128(ctr5, rk);
        }

        const __m256i rkLast = _mm256_broadcastsi128_si256(roundKeys[r]);
        ctr0 = _mm256_aesenclast_epi128(ctr0, rkLast);
        ctr1 = _mm256_aesenclast_epi128(ctr1, rkLast);
        ctr2 = _mm256_aesenclast_epi128(ctr2, rkLast);
        ctr3 = _mm256_aesenclast_epi128(ctr3, rkLast);
        ctr4 = _mm256_aesenclast_epi128(ctr4, rkLast);
        ctr5 = _mm256_aesenclast_epi128(ctr5, rkLast);

        *d0 = _mm256_xor_si256(ctr0, *d0);
        *d1 = _mm256_xor_si256(ctr1, *d1);
        *d2 = _mm256_xor_si256(ctr2, *d2);
        *d3 = _mm256_xor_si256(ctr3, *d3);
        *d4 = _mm256_xor_si256(ctr4, *d4);
        *d5 = _mm256_xor_si256(ctr5, *d5);

    } else if (blocks == 10) {
        ctr0 = _mm256_add_epi64(_mm256_broadcastsi128_si256(ctr), *SPREAD_256);
        ctr1 = _mm256_add_epi64(ctr0, *INC_CTR_256);
        ctr2 = _mm256_add_epi64(ctr1, *INC_CTR_256);
        ctr3 = _mm256_add_epi64(ctr2, *INC_CTR_256);
        ctr4 = _mm256_add_epi64(ctr3, *INC_CTR_256);

        ctr0 = _mm256_shuffle_epi8(ctr0, *SWAP_ENDIAN_256);
        ctr1 = _mm256_shuffle_epi8(ctr1, *SWAP_ENDIAN_256);
        ctr2 = _mm256_shuffle_epi8(ctr2, *SWAP_ENDIAN_256);
        ctr3 = _mm256_shuffle_epi8(ctr3, *SWAP_ENDIAN_256);
        ctr4 = _mm256_shuffle_epi8(ctr4, *SWAP_ENDIAN_256);

        const __m256i rk0 = _mm256_broadcastsi128_si256(roundKeys[0]);
        ctr0 = _mm256_xor_si256(ctr0, rk0);
        ctr1 = _mm256_xor_si256(ctr1, rk0);
        ctr2 = _mm256_xor_si256(ctr2, rk0);
        ctr3 = _mm256_xor_si256(ctr3, rk0);
        ctr4 = _mm256_xor_si256(ctr4, rk0);

        int r;
        for (r = 1; r < max_rounds; r++) {
            const __m256i rk = _mm256_broadcastsi128_si256(roundKeys[r]);
            ctr0 = _mm256_aesenc_epi128(ctr0, rk);
            ctr1 = _mm256_aesenc_epi128(ctr1, rk);
            ctr2 = _mm256_aesenc_epi128(ctr2, rk);
            ctr3 = _mm256_aesenc_epi128(ctr3, rk);
            ctr4 = _mm256_aesenc_epi128(ctr4, rk);
        }

        const __m256i rkLast = _mm256_broadcastsi128_si256(roundKeys[r]);
        ctr0 = _mm256_aesenclast_epi128(ctr0, rkLast);
        ctr1 = _mm256_aesenclast_epi128(ctr1, rkLast);
        ctr2 = _mm256_aesenclast_epi128(ctr2, rkLast);
        ctr3 = _mm256_aesenclast_epi128(ctr3, rkLast);
        ctr4 = _mm256_aesenclast_epi128(ctr4, rkLast);

        *d0 = _mm256_xor_si256(ctr0, *d0);
        *d1 = _mm256_xor_si256(ctr1, *d1);
        *d2 = _mm256_xor_si256(ctr2, *d2);
        *d3 = _mm256_xor_si256(ctr3, *d3);
        *d4 = _mm256_xor_si256(ctr4, *d4);
    } else if (blocks == 8) {
        ctr0 = _mm256_add_epi64(_mm256_broadcastsi128_si256(ctr), *SPREAD_256);
        ctr1 = _mm256_add_epi64(ctr0, *INC_CTR_256);
        ctr2 = _mm256_add_epi64(ctr1, *INC_CTR_256);
        ctr3 = _mm256_add_epi64(ctr2, *INC_CTR_256);

        ctr0 = _mm256_shuffle_epi8(ctr0, *SWAP_ENDIAN_256);
        ctr1 = _mm256_shuffle_epi8(ctr1, *SWAP_ENDIAN_256);
        ctr2 = _mm256_shuffle_epi8(ctr2, *SWAP_ENDIAN_256);
        ctr3 = _mm256_shuffle_epi8(ctr3, *SWAP_ENDIAN_256);

        const __m256i rk0 = _mm256_broadcastsi128_si256(roundKeys[0]);
        ctr0 = _mm256_xor_si256(ctr0, rk0);
        ctr1 = _mm256_xor_si256(ctr1, rk0);
        ctr2 = _mm256_xor_si256(ctr2, rk0);
        ctr3 = _mm256_xor_si256(ctr3, rk0);

        int r;
        for (r = 1; r < max_rounds; r++) {
            const __m256i rk = _mm256_broadcastsi128_si256(roundKeys[r]);
            ctr0 = _mm256_aesenc_epi128(ctr0, rk);
            ctr1 = _mm256_aesenc_epi128(ctr1, rk);
            ctr2 = _mm256_aesenc_epi128(ctr2, rk);
            ctr3 = _mm256_aesenc_epi128(ctr3, rk);
        }

        const __m256i rkLast = _mm256_broadcastsi128_si256(roundKeys[r]);
        ctr0 = _mm256_aesenclast_epi128(ctr0, rkLast);
        ctr1 = _mm256_aesenclast_epi128(ctr1, rkLast);
        ctr2 = _mm256_aesenclast_epi128(ctr2, rkLast);
        ctr3 = _mm256_aesenclast_epi128(ctr3, rkLast);


        *d0 = _mm256_xor_si256(ctr0, *d0);
        *d1 = _mm256_xor_si256(ctr1, *d1);
        *d2 = _mm256_xor_si256(ctr2, *d2);
        *d3 = _mm256_xor_si256(ctr3, *d3);
    } else if (blocks == 6) {
        ctr0 = _mm256_add_epi64(_mm256_broadcastsi128_si256(ctr), *SPREAD_256);
        ctr1 = _mm256_add_epi64(ctr0, *INC_CTR_256);
        ctr2 = _mm256_add_epi64(ctr1, *INC_CTR_256);

        ctr0 = _mm256_shuffle_epi8(ctr0, *SWAP_ENDIAN_256);
        ctr1 = _mm256_shuffle_epi8(ctr1, *SWAP_ENDIAN_256);
        ctr2 = _mm256_shuffle_epi8(ctr2, *SWAP_ENDIAN_256);

        const __m256i rk0 = _mm256_broadcastsi128_si256(roundKeys[0]);
        ctr0 = _mm256_xor_si256(ctr0, rk0);
        ctr1 = _mm256_xor_si256(ctr1, rk0);
        ctr2 = _mm256_xor_si256(ctr2, rk0);

        int r;
        for (r = 1; r < max_rounds; r++) {
            const __m256i rk = _mm256_broadcastsi128_si256(roundKeys[r]);
            ctr0 = _mm256_aesenc_epi128(ctr0, rk);
            ctr1 = _mm256_aesenc_epi128(ctr1, rk);
            ctr2 = _mm256_aesenc_epi128(ctr2, rk);
        }

        const __m256i rkLast = _mm256_broadcastsi128_si256(roundKeys[r]);
        ctr0 = _mm256_aesenclast_epi128(ctr0, rkLast);
        ctr1 = _mm256_aesenclast_epi128(ctr1, rkLast);
        ctr2 = _mm256_aesenclast_epi128(ctr2, rkLast);

        *d0 = _mm256_xor_si256(ctr0, *d0);
        *d1 = _mm256_xor_si256(ctr1, *d1);
        *d2 = _mm256_xor_si256(ctr2, *d2);
    } else if (blocks == 4) {
        ctr0 = _mm256_add_epi64(_mm256_broadcastsi128_si256(ctr), *SPREAD_256);
        ctr1 = _mm256_add_epi64(ctr0, *INC_CTR_256);

        ctr0 = _mm256_shuffle_epi8(ctr0, *SWAP_ENDIAN_256);
        ctr1 = _mm256_shuffle_epi8(ctr1, *SWAP_ENDIAN_256);

        const __m256i rk0 = _mm256_broadcastsi128_si256(roundKeys[0]);
        ctr0 = _mm256_xor_si256(ctr0, rk0);
        ctr1 = _mm256_xor_si256(ctr1, rk0);

        int r;
        for (r = 1; r < max_rounds; r++) {
            const __m256i rk = _mm256_broadcastsi128_si256(roundKeys[r]);
            ctr0 = _mm256_aesenc_epi128(ctr0, rk);
            ctr1 = _mm256_aesenc_epi128(ctr1, rk);
        }

        const __m256i rkLast = _mm256_broadcastsi128_si256(roundKeys[r]);
        ctr0 = _mm256_aesenclast_epi128(ctr0, rkLast);
        ctr1 = _mm256_aesenclast_epi128(ctr1, rkLast);


        *d0 = _mm256_xor_si256(ctr0, *d0);
        *d1 = _mm256_xor_si256(ctr1, *d1);

    } else if (blocks == 2) {
        ctr0 = _mm256_add_epi64(_mm256_broadcastsi128_si256(ctr), *SPREAD_256);
        ctr0 = _mm256_shuffle_epi8(ctr0, *SWAP_ENDIAN_256);

        const __m256i rk0 = _mm256_broadcastsi128_si256(roundKeys[0]);
        ctr0 = _mm256_xor_si256(ctr0, rk0);


        int r;
        for (r = 1; r < max_rounds; r++) {
            const __m256i rk = _mm256_broadcastsi128_si256(roundKeys[r]);
            ctr0 = _mm256_aesenc_epi128(ctr0, rk);
        }

        const __m256i rkLast = _mm256_broadcastsi128_si256(roundKeys[r]);
        ctr0 = _mm256_aesenclast_epi128(ctr0, rkLast);

        *d0 = _mm256_xor_si256(ctr0, *d0);

    } else {
        ctr0 = _mm256_broadcastsi128_si256(ctr); // note lack of counter spread.
        ctr0 = _mm256_shuffle_epi8(ctr0, *SWAP_ENDIAN_256);

        const __m256i rk0 = _mm256_broadcastsi128_si256(roundKeys[0]);
        ctr0 = _mm256_xor_si256(ctr0, rk0);
        int r;
        for (r = 1; r < max_rounds; r++) {
            ctr0 = _mm256_aesenc_epi128(ctr0, _mm256_broadcastsi128_si256(roundKeys[r]));
        }

        ctr0 = _mm256_aesenclast_epi128(ctr0, _mm256_broadcastsi128_si256(roundKeys[r]));
        *d0 = _mm256_xor_si256(ctr0, *d0);

    }

}

bool ctr_process_bytes(ctr_ctx *pCtr, unsigned char *src, size_t len, unsigned char *dest, size_t *written) {

    unsigned char *destStart = dest;

    // Round out any buffered content.
    while (pCtr->buf_pos > 0 && pCtr->buf_pos < CTR_BLOCK_SIZE && len > 0) {

        unsigned char v = *src;
        if (!ctr_process_byte(pCtr, &v)) {
            return false;
        }
        *dest = v;
        src++;
        dest++;
        len--;
    }

    if (pCtr->buf_pos == 0 && len >= 16) {

        while (len >= CTR_BLOCK_SIZE) {


            uint64_t blockIndex = (pCtr->ctr - pCtr->initialCTR) & pCtr->ctrMask;
            uint64_t lastBlockIndex = pCtr->ctrMask;

            const uint64_t  ctr = pCtr->ctr;

            if (len >= 16 * CTR_BLOCK_SIZE) {
                if (!ctr_incCtr(pCtr,16)) {
                    return false;
                }

                const __m128i c0 = _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (int64_t)ctr));
                __m256i d0 = _mm256_loadu_si256((__m256i *) &src[0 * 32]);
                __m256i d1 = _mm256_loadu_si256((__m256i *) &src[1 * 32]);
                __m256i d2 = _mm256_loadu_si256((__m256i *) &src[2 * 32]);
                __m256i d3 = _mm256_loadu_si256((__m256i *) &src[3 * 32]);
                __m256i d4 = _mm256_loadu_si256((__m256i *) &src[4 * 32]);
                __m256i d5 = _mm256_loadu_si256((__m256i *) &src[5 * 32]);
                __m256i d6 = _mm256_loadu_si256((__m256i *) &src[6 * 32]);
                __m256i d7 = _mm256_loadu_si256((__m256i *) &src[7 * 32]);

                aes_ctr256_wide(&d0, &d1, &d2, &d3, &d4, &d5, &d6, &d7, pCtr->roundKeys, c0, pCtr->num_rounds, 16);

                _mm256_storeu_si256((__m256i *) &dest[0 * 32], d0);
                _mm256_storeu_si256((__m256i *) &dest[1 * 32], d1);
                _mm256_storeu_si256((__m256i *) &dest[2 * 32], d2);
                _mm256_storeu_si256((__m256i *) &dest[3 * 32], d3);
                _mm256_storeu_si256((__m256i *) &dest[4 * 32], d4);
                _mm256_storeu_si256((__m256i *) &dest[5 * 32], d5);
                _mm256_storeu_si256((__m256i *) &dest[6 * 32], d6);
                _mm256_storeu_si256((__m256i *) &dest[7 * 32], d7);

                len -= 16 * CTR_BLOCK_SIZE;
                src += 16 * CTR_BLOCK_SIZE;
                dest += 16 * CTR_BLOCK_SIZE;


            } else if (len >= 14 * CTR_BLOCK_SIZE) {
                if (!ctr_incCtr(pCtr,14)) {
                    return false;
                }
                const __m128i c0 = _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (int64_t)ctr));
                __m256i d0 = _mm256_loadu_si256((__m256i *) &src[0 * 32]);
                __m256i d1 = _mm256_loadu_si256((__m256i *) &src[1 * 32]);
                __m256i d2 = _mm256_loadu_si256((__m256i *) &src[2 * 32]);
                __m256i d3 = _mm256_loadu_si256((__m256i *) &src[3 * 32]);
                __m256i d4 = _mm256_loadu_si256((__m256i *) &src[4 * 32]);
                __m256i d5 = _mm256_loadu_si256((__m256i *) &src[5 * 32]);
                __m256i d6 = _mm256_loadu_si256((__m256i *) &src[6 * 32]);


                aes_ctr256_wide(&d0, &d1, &d2, &d3, &d4, &d5, &d6, &d6, pCtr->roundKeys, c0, pCtr->num_rounds, 14);

                _mm256_storeu_si256((__m256i *) &dest[0 * 32], d0);
                _mm256_storeu_si256((__m256i *) &dest[1 * 32], d1);
                _mm256_storeu_si256((__m256i *) &dest[2 * 32], d2);
                _mm256_storeu_si256((__m256i *) &dest[3 * 32], d3);
                _mm256_storeu_si256((__m256i *) &dest[4 * 32], d4);
                _mm256_storeu_si256((__m256i *) &dest[5 * 32], d5);
                _mm256_storeu_si256((__m256i *) &dest[6 * 32], d6);


                len -= 14 * CTR_BLOCK_SIZE;
                src += 14 * CTR_BLOCK_SIZE;
                dest += 14 * CTR_BLOCK_SIZE;

            } else if (len >= 12 * CTR_BLOCK_SIZE) {
                if (!ctr_incCtr(pCtr,12)) {
                    return false;
                }
                const __m128i c0 = _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (int64_t)ctr));
                __m256i d0 = _mm256_loadu_si256((__m256i *) &src[0 * 32]);
                __m256i d1 = _mm256_loadu_si256((__m256i *) &src[1 * 32]);
                __m256i d2 = _mm256_loadu_si256((__m256i *) &src[2 * 32]);
                __m256i d3 = _mm256_loadu_si256((__m256i *) &src[3 * 32]);
                __m256i d4 = _mm256_loadu_si256((__m256i *) &src[4 * 32]);
                __m256i d5 = _mm256_loadu_si256((__m256i *) &src[5 * 32]);

                aes_ctr256_wide(&d0, &d1, &d2, &d3, &d4, &d5, &d5, &d5, pCtr->roundKeys, c0, pCtr->num_rounds, 12);

                _mm256_storeu_si256((__m256i *) &dest[0 * 32], d0);
                _mm256_storeu_si256((__m256i *) &dest[1 * 32], d1);
                _mm256_storeu_si256((__m256i *) &dest[2 * 32], d2);
                _mm256_storeu_si256((__m256i *) &dest[3 * 32], d3);
                _mm256_storeu_si256((__m256i *) &dest[4 * 32], d4);
                _mm256_storeu_si256((__m256i *) &dest[5 * 32], d5);

                len -= 12 * CTR_BLOCK_SIZE;
                src += 12 * CTR_BLOCK_SIZE;
                dest += 12 * CTR_BLOCK_SIZE;
            } else if (len >= 10 * CTR_BLOCK_SIZE) {
                if (!ctr_incCtr(pCtr,10)) {
                    return false;
                }
                const __m128i c0 = _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (int64_t)ctr));
                __m256i d0 = _mm256_loadu_si256((__m256i *) &src[0 * 32]);
                __m256i d1 = _mm256_loadu_si256((__m256i *) &src[1 * 32]);
                __m256i d2 = _mm256_loadu_si256((__m256i *) &src[2 * 32]);
                __m256i d3 = _mm256_loadu_si256((__m256i *) &src[3 * 32]);
                __m256i d4 = _mm256_loadu_si256((__m256i *) &src[4 * 32]);

                aes_ctr256_wide(&d0, &d1, &d2, &d3, &d4, &d4, &d4, &d4, pCtr->roundKeys, c0, pCtr->num_rounds, 10);

                _mm256_storeu_si256((__m256i *) &dest[0 * 32], d0);
                _mm256_storeu_si256((__m256i *) &dest[1 * 32], d1);
                _mm256_storeu_si256((__m256i *) &dest[2 * 32], d2);
                _mm256_storeu_si256((__m256i *) &dest[3 * 32], d3);
                _mm256_storeu_si256((__m256i *) &dest[4 * 32], d4);


                len -= 10 * CTR_BLOCK_SIZE;
                src += 10 * CTR_BLOCK_SIZE;
                dest += 10 * CTR_BLOCK_SIZE;
            } else if (len >= 8 * CTR_BLOCK_SIZE) {
                if (!ctr_incCtr(pCtr,8)) {
                    return false;
                }
                const __m128i c0 = _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (int64_t)ctr));
                __m256i d0 = _mm256_loadu_si256((__m256i *) &src[0 * 32]);
                __m256i d1 = _mm256_loadu_si256((__m256i *) &src[1 * 32]);
                __m256i d2 = _mm256_loadu_si256((__m256i *) &src[2 * 32]);
                __m256i d3 = _mm256_loadu_si256((__m256i *) &src[3 * 32]);


                aes_ctr256_wide(&d0, &d1, &d2, &d3, &d3, &d3, &d3, &d3, pCtr->roundKeys, c0, pCtr->num_rounds, 8);

                _mm256_storeu_si256((__m256i *) &dest[0 * 32], d0);
                _mm256_storeu_si256((__m256i *) &dest[1 * 32], d1);
                _mm256_storeu_si256((__m256i *) &dest[2 * 32], d2);
                _mm256_storeu_si256((__m256i *) &dest[3 * 32], d3);

                len -= 8 * CTR_BLOCK_SIZE;
                src += 8 * CTR_BLOCK_SIZE;
                dest += 8 * CTR_BLOCK_SIZE;
            } else if (len >= 6 * CTR_BLOCK_SIZE) {
                if (!ctr_incCtr(pCtr,6)) {
                    return false;
                }
                const __m128i c0 = _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (int64_t)ctr));
                __m256i d0 = _mm256_loadu_si256((__m256i *) &src[0 * 32]);
                __m256i d1 = _mm256_loadu_si256((__m256i *) &src[1 * 32]);
                __m256i d2 = _mm256_loadu_si256((__m256i *) &src[2 * 32]);


                aes_ctr256_wide(&d0, &d1, &d2, &d2, &d2, &d2, &d2, &d2, pCtr->roundKeys, c0, pCtr->num_rounds, 6);

                _mm256_storeu_si256((__m256i *) &dest[0 * 32], d0);
                _mm256_storeu_si256((__m256i *) &dest[1 * 32], d1);
                _mm256_storeu_si256((__m256i *) &dest[2 * 32], d2);

                len -= 6 * CTR_BLOCK_SIZE;
                src += 6 * CTR_BLOCK_SIZE;
                dest += 6 * CTR_BLOCK_SIZE;

            } else if (len >= 4 * CTR_BLOCK_SIZE) {
                if (!ctr_incCtr(pCtr,4)) {
                    return false;
                }
                const __m128i c0 = _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (int64_t)ctr));
                __m256i d0 = _mm256_loadu_si256((__m256i *) &src[0 * 32]);
                __m256i d1 = _mm256_loadu_si256((__m256i *) &src[1 * 32]);


                aes_ctr256_wide(&d0, &d1, &d1, &d1, &d1, &d1, &d1, &d1, pCtr->roundKeys, c0, pCtr->num_rounds, 4);

                _mm256_storeu_si256((__m256i *) &dest[0 * 32], d0);
                _mm256_storeu_si256((__m256i *) &dest[1 * 32], d1);

                len -= 4 * CTR_BLOCK_SIZE;
                src += 4 * CTR_BLOCK_SIZE;
                dest += 4 * CTR_BLOCK_SIZE;
            } else if (len >= 2 * CTR_BLOCK_SIZE) {
                if (!ctr_incCtr(pCtr,2)) {
                    return false;
                }
                const __m128i c0 = _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (int64_t)ctr));
                __m256i d0 = _mm256_loadu_si256((__m256i *) &src[0 * 32]);


                aes_ctr256_wide(&d0, &d0, &d0, &d0, &d0, &d0, &d0, &d0, pCtr->roundKeys, c0, pCtr->num_rounds, 2);

                _mm256_storeu_si256((__m256i *) &dest[0 * 32], d0);


                len -= 2 * CTR_BLOCK_SIZE;
                src += 2 * CTR_BLOCK_SIZE;
                dest += 2 * CTR_BLOCK_SIZE;
            } else {

                // one block
                if (!ctr_incCtr(pCtr,1)) {
                    return false;
                }

                const __m128i c0 = _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (int64_t) ctr));

                // same data is broadcast into both halves of 256b vector

                __m256i d0 = _mm256_broadcastsi128_si256(_mm_loadu_si128((__m128i *) &src[0 * 16]));


                aes_ctr256_wide(&d0, &d0, &d0, &d0, &d0, &d0, &d0, &d0, pCtr->roundKeys, c0, pCtr->num_rounds, 1);


                _mm_storeu_si128((__m128i *) &dest[0 * 16], _mm256_castsi256_si128(d0));

                len -= CTR_BLOCK_SIZE;
                src += CTR_BLOCK_SIZE;
                dest += CTR_BLOCK_SIZE;

            }

        }
    }


    while (len > 0) {

        unsigned char v = *src;

        if (!ctr_process_byte(pCtr, &v)) {
            return false;
        }
        *dest = v;
        src++;
        dest++;
        len--;
    }

    *written = (size_t) (dest - destStart);
    return true;

}



#endif //BC_FIPS_AES_CTR256_H
