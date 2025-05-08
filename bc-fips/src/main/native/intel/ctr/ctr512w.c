


#include <immintrin.h>
#include <stdbool.h>
#include "ctr.h"


static const int8_t __attribute__ ((aligned(64))) _swap_endian_512[64] = {
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
};

static const __m512i *SWAP_ENDIAN_512 = ((__m512i *) _swap_endian_512);


static const uint32_t __attribute__ ((aligned(64))) _inc_512_ctr[16] = {
        4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0
};

static __m512i *INC_CTR_512 = (__m512i *) _inc_512_ctr;


static const uint32_t  __attribute__ ((aligned(64))) _spread_512[16] = {
        0, 0, 0, 0, 1, 0, 0, 0,
        2, 0, 0, 0, 3, 0, 0, 0
};

static __m512i *SPREAD_512 = (__m512i *) _spread_512;


static const int8_t __attribute__ ((aligned(32))) _swap_endian_256[32] = {
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
};

static const __m256i *SWAP_ENDIAN_256 = ((__m256i *) _swap_endian_256);


static const uint32_t __attribute__ ((aligned(32))) _inc_256_ctr[8] = {
        2, 0, 0, 0, 2, 0, 0, 0
};

static __m256i *INC_CTR_256 = (__m256i *) _inc_256_ctr;


static const uint32_t __attribute__ ((aligned(32))) _spread_256[8] = {
        0, 0, 0, 0, 1, 0, 0, 0
};

static __m256i *SPREAD_256 = (__m256i *) _spread_256;


static inline void aes_ctr512_wide(__m512i *d0, __m512i *d1, __m512i *d2, __m512i *d3,
                                   __m128i *roundKeys, const __m128i ctr, const uint32_t max_rounds,
                                   const uint32_t blocks) {

    __m512i ctr0, ctr1, ctr2, ctr3;

    if (blocks == 16) {
        ctr0 = _mm512_add_epi64(_mm512_broadcast_i32x4(ctr), *SPREAD_512);
        ctr1 = _mm512_add_epi64(ctr0, *INC_CTR_512);
        ctr2 = _mm512_add_epi64(ctr1, *INC_CTR_512);
        ctr3 = _mm512_add_epi64(ctr2, *INC_CTR_512);


        ctr0 = _mm512_shuffle_epi8(ctr0, *SWAP_ENDIAN_512);
        ctr1 = _mm512_shuffle_epi8(ctr1, *SWAP_ENDIAN_512);
        ctr2 = _mm512_shuffle_epi8(ctr2, *SWAP_ENDIAN_512);
        ctr3 = _mm512_shuffle_epi8(ctr3, *SWAP_ENDIAN_512);

        const __m512i rk0 = _mm512_broadcast_i32x4(roundKeys[0]);
        ctr0 = _mm512_xor_si512(ctr0, rk0);
        ctr1 = _mm512_xor_si512(ctr1, rk0);
        ctr2 = _mm512_xor_si512(ctr2, rk0);
        ctr3 = _mm512_xor_si512(ctr3, rk0);


        int r;
        for (r = 1; r < max_rounds; r++) {
            const __m512i rk = _mm512_broadcast_i32x4(roundKeys[r]);
            ctr0 = _mm512_aesenc_epi128(ctr0, rk);
            ctr1 = _mm512_aesenc_epi128(ctr1, rk);
            ctr2 = _mm512_aesenc_epi128(ctr2, rk);
            ctr3 = _mm512_aesenc_epi128(ctr3, rk);

        }

        const __m512i rkLast = _mm512_broadcast_i32x4(roundKeys[r]);
        ctr0 = _mm512_aesenclast_epi128(ctr0, rkLast);
        ctr1 = _mm512_aesenclast_epi128(ctr1, rkLast);
        ctr2 = _mm512_aesenclast_epi128(ctr2, rkLast);
        ctr3 = _mm512_aesenclast_epi128(ctr3, rkLast);


        *d0 = _mm512_xor_si512(ctr0, *d0);
        *d1 = _mm512_xor_si512(ctr1, *d1);
        *d2 = _mm512_xor_si512(ctr2, *d2);
        *d3 = _mm512_xor_si512(ctr3, *d3);


    } else if (blocks == 12) {
        ctr0 = _mm512_add_epi64(_mm512_broadcast_i32x4(ctr), *SPREAD_512);
        ctr1 = _mm512_add_epi64(ctr0, *INC_CTR_512);
        ctr2 = _mm512_add_epi64(ctr1, *INC_CTR_512);


        ctr0 = _mm512_shuffle_epi8(ctr0, *SWAP_ENDIAN_512);
        ctr1 = _mm512_shuffle_epi8(ctr1, *SWAP_ENDIAN_512);
        ctr2 = _mm512_shuffle_epi8(ctr2, *SWAP_ENDIAN_512);


        const __m512i rk0 = _mm512_broadcast_i32x4(roundKeys[0]);
        ctr0 = _mm512_xor_si512(ctr0, rk0);
        ctr1 = _mm512_xor_si512(ctr1, rk0);
        ctr2 = _mm512_xor_si512(ctr2, rk0);


        int r;
        for (r = 1; r < max_rounds; r++) {
            const __m512i rk = _mm512_broadcast_i32x4(roundKeys[r]);
            ctr0 = _mm512_aesenc_epi128(ctr0, rk);
            ctr1 = _mm512_aesenc_epi128(ctr1, rk);
            ctr2 = _mm512_aesenc_epi128(ctr2, rk);
        }

        const __m512i rkLast = _mm512_broadcast_i32x4(roundKeys[r]);
        ctr0 = _mm512_aesenclast_epi128(ctr0, rkLast);
        ctr1 = _mm512_aesenclast_epi128(ctr1, rkLast);
        ctr2 = _mm512_aesenclast_epi128(ctr2, rkLast);


        *d0 = _mm512_xor_si512(ctr0, *d0);
        *d1 = _mm512_xor_si512(ctr1, *d1);
        *d2 = _mm512_xor_si512(ctr2, *d2);


    } else if (blocks == 8) {
        ctr0 = _mm512_add_epi64(_mm512_broadcast_i32x4(ctr), *SPREAD_512);
        ctr1 = _mm512_add_epi64(ctr0, *INC_CTR_512);

        ctr0 = _mm512_shuffle_epi8(ctr0, *SWAP_ENDIAN_512);
        ctr1 = _mm512_shuffle_epi8(ctr1, *SWAP_ENDIAN_512);

        const __m512i rk0 = _mm512_broadcast_i32x4(roundKeys[0]);
        ctr0 = _mm512_xor_si512(ctr0, rk0);
        ctr1 = _mm512_xor_si512(ctr1, rk0);

        int r;
        for (r = 1; r < max_rounds; r++) {
            const __m512i rk = _mm512_broadcast_i32x4(roundKeys[r]);
            ctr0 = _mm512_aesenc_epi128(ctr0, rk);
            ctr1 = _mm512_aesenc_epi128(ctr1, rk);
        }

        const __m512i rkLast = _mm512_broadcast_i32x4(roundKeys[r]);
        ctr0 = _mm512_aesenclast_epi128(ctr0, rkLast);
        ctr1 = _mm512_aesenclast_epi128(ctr1, rkLast);

        *d0 = _mm512_xor_si512(ctr0, *d0);
        *d1 = _mm512_xor_si512(ctr1, *d1);

    } else {
        ctr0 = _mm512_add_epi64(_mm512_broadcast_i32x4(ctr), *SPREAD_512);

        ctr0 = _mm512_shuffle_epi8(ctr0, *SWAP_ENDIAN_512);

        const __m512i rk0 = _mm512_broadcast_i32x4(roundKeys[0]);
        ctr0 = _mm512_xor_si512(ctr0, rk0);

        int r;
        for (r = 1; r < max_rounds; r++) {
            const __m512i rk = _mm512_broadcast_i32x4(roundKeys[r]);
            ctr0 = _mm512_aesenc_epi128(ctr0, rk);
        }

        const __m512i rkLast = _mm512_broadcast_i32x4(roundKeys[r]);
        ctr0 = _mm512_aesenclast_epi128(ctr0, rkLast);

        *d0 = _mm512_xor_si512(ctr0, *d0);
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

          const uint64_t  ctr = pCtr->ctr;

            if (len >= 16 * CTR_BLOCK_SIZE) {

                if (!ctr_incCtr(pCtr,16)) {
                    return false;
                }
                const __m128i c0 = _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (int64_t) ctr));
                __m512i d0 = _mm512_loadu_si512((__m512i *) &src[0 * 64]);
                __m512i d1 = _mm512_loadu_si512((__m512i *) &src[1 * 64]);
                __m512i d2 = _mm512_loadu_si512((__m512i *) &src[2 * 64]);
                __m512i d3 = _mm512_loadu_si512((__m512i *) &src[3 * 64]);


                aes_ctr512_wide(&d0, &d1, &d2, &d3, pCtr->roundKeys, c0, pCtr->num_rounds, 16);

                _mm512_storeu_si512((__m256i *) &dest[0 * 64], d0);
                _mm512_storeu_si512((__m256i *) &dest[1 * 64], d1);
                _mm512_storeu_si512((__m256i *) &dest[2 * 64], d2);
                _mm512_storeu_si512((__m256i *) &dest[3 * 64], d3);


                len -= 16 * CTR_BLOCK_SIZE;
                src += 16 * CTR_BLOCK_SIZE;
                dest += 16 * CTR_BLOCK_SIZE;

            } else if (len >= 12 * CTR_BLOCK_SIZE) {
                if (!ctr_incCtr(pCtr,12)) {
                    return false;
                }
                const __m128i c0 = _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (int64_t) ctr));
                __m512i d0 = _mm512_loadu_si512((__m512i *) &src[0 * 64]);
                __m512i d1 = _mm512_loadu_si512((__m512i *) &src[1 * 64]);
                __m512i d2 = _mm512_loadu_si512((__m512i *) &src[2 * 64]);

                aes_ctr512_wide(&d0, &d1, &d2, &d2, pCtr->roundKeys, c0, pCtr->num_rounds, 12);

                _mm512_storeu_si512((__m256i *) &dest[0 * 64], d0);
                _mm512_storeu_si512((__m256i *) &dest[1 * 64], d1);
                _mm512_storeu_si512((__m256i *) &dest[2 * 64], d2);

                len -= 12 * CTR_BLOCK_SIZE;
                src += 12 * CTR_BLOCK_SIZE;
                dest += 12 * CTR_BLOCK_SIZE;
            } else if (len >= 8 * CTR_BLOCK_SIZE) {
                if (!ctr_incCtr(pCtr,8)) {
                    return false;
                }
                const __m128i c0 = _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (int64_t) ctr));
                __m512i d0 = _mm512_loadu_si512((__m512i *) &src[0 * 64]);
                __m512i d1 = _mm512_loadu_si512((__m512i *) &src[1 * 64]);


                aes_ctr512_wide(&d0, &d1, &d1, &d1, pCtr->roundKeys, c0, pCtr->num_rounds, 8);

                _mm512_storeu_si512((__m256i *) &dest[0 * 64], d0);
                _mm512_storeu_si512((__m256i *) &dest[1 * 64], d1);


                len -= 8 * CTR_BLOCK_SIZE;
                src += 8 * CTR_BLOCK_SIZE;
                dest += 8 * CTR_BLOCK_SIZE;
            } else if (len >= 4 * CTR_BLOCK_SIZE) {

                if (!ctr_incCtr(pCtr,4)) {
                    return false;
                }
                const __m128i c0 = _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (int64_t) ctr));
                __m512i d0 = _mm512_loadu_si512((__m512i *) &src[0 * 64]);

                aes_ctr512_wide(&d0, &d0, &d0, &d0, pCtr->roundKeys, c0, pCtr->num_rounds, 4);

                _mm512_storeu_si512((__m512i *) &dest[0 * 64], d0);


                len -= 4 * CTR_BLOCK_SIZE;
                src += 4 * CTR_BLOCK_SIZE;
                dest += 4 * CTR_BLOCK_SIZE;

            } else if (len >= 2 * CTR_BLOCK_SIZE) {
                if (!ctr_incCtr(pCtr,2)) {
                    return false;
                }
                const __m128i c0 = _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (int64_t) ctr));
                __m256i d0 = _mm256_loadu_si256((__m256i *) &src[0 * 32]);

                __m256i ctr0 = _mm256_add_epi64(_mm256_broadcastsi128_si256(c0), *SPREAD_256);
                ctr0 = _mm256_shuffle_epi8(ctr0, *SWAP_ENDIAN_256);

                const __m256i rk0 = _mm256_broadcastsi128_si256(pCtr->roundKeys[0]);
                ctr0 = _mm256_xor_si256(ctr0, rk0);


                int r;
                for (r = 1; r < pCtr->num_rounds; r++) {
                    const __m256i rk = _mm256_broadcastsi128_si256(pCtr->roundKeys[r]);
                    ctr0 = _mm256_aesenc_epi128(ctr0, rk);
                }

                const __m256i rkLast = _mm256_broadcastsi128_si256(pCtr->roundKeys[r]);
                ctr0 = _mm256_aesenclast_epi128(ctr0, rkLast);

                d0 = _mm256_xor_si256(ctr0, d0);

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

                __m128i d0 = _mm_loadu_si128((__m128i *) &src[0 * 16]);


                __m128i t0 = _mm_shuffle_epi8(c0, *SWAP_ENDIAN_128);
                const __m128i rkFirst = pCtr->roundKeys[0];

                t0 = _mm_xor_si128(t0, rkFirst);

                int round;
                for (round = 1; round < pCtr->num_rounds; round++) {
                    const __m128i rk = pCtr->roundKeys[round];
                    t0 = _mm_aesenc_si128(t0, rk);
                }

                const __m128i rkLast = pCtr->roundKeys[round];
                t0 = _mm_aesenclast_si128(t0, rkLast);

                d0 = _mm_xor_si128(d0, t0);

                _mm_storeu_si128((__m128i *) &dest[0 * 16], d0);

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


