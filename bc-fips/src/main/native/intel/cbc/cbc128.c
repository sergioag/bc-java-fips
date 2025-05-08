

#include <stddef.h>
#include <assert.h>
#include "cbc.h"

//
// AVX or 128b single block implementation.
//


static inline void aesdec_8_blocks_128b(__m128i *b1, __m128i *b2, __m128i *b3, __m128i *b4,
                                        __m128i *b5, __m128i *b6, __m128i *b7, __m128i *b8,
                                        const __m128i *round_keys, const int num_rounds,
                                        const int num_blocks) {

    const __m128i rk_ark = round_keys[0];

    *b1 = _mm_xor_si128(*b1, rk_ark);
    if (num_blocks > 1)
        *b2 = _mm_xor_si128(*b2, rk_ark);
    if (num_blocks > 2)
        *b3 = _mm_xor_si128(*b3, rk_ark);
    if (num_blocks > 3)
        *b4 = _mm_xor_si128(*b4, rk_ark);
    if (num_blocks > 4)
        *b5 = _mm_xor_si128(*b5, rk_ark);
    if (num_blocks > 5)
        *b6 = _mm_xor_si128(*b6, rk_ark);
    if (num_blocks > 6)
        *b7 = _mm_xor_si128(*b7, rk_ark);
    if (num_blocks > 7)
        *b8 = _mm_xor_si128(*b8, rk_ark);

    int round;
    for (round = 1; round < num_rounds; round++) {
        const __m128i rk = round_keys[round];

        *b1 = _mm_aesdec_si128(*b1, rk);
        if (num_blocks > 1)
            *b2 = _mm_aesdec_si128(*b2, rk);
        if (num_blocks > 2)
            *b3 = _mm_aesdec_si128(*b3, rk);
        if (num_blocks > 3)
            *b4 = _mm_aesdec_si128(*b4, rk);
        if (num_blocks > 4)
            *b5 = _mm_aesdec_si128(*b5, rk);
        if (num_blocks > 5)
            *b6 = _mm_aesdec_si128(*b6, rk);
        if (num_blocks > 6)
            *b7 = _mm_aesdec_si128(*b7, rk);
        if (num_blocks > 7)
            *b8 = _mm_aesdec_si128(*b8, rk);
    }

    const __m128i rk_last = round_keys[round];

    *b1 = _mm_aesdeclast_si128(*b1, rk_last);
    if (num_blocks > 1)
        *b2 = _mm_aesdeclast_si128(*b2, rk_last);
    if (num_blocks > 2)
        *b3 = _mm_aesdeclast_si128(*b3, rk_last);
    if (num_blocks > 3)
        *b4 = _mm_aesdeclast_si128(*b4, rk_last);
    if (num_blocks > 4)
        *b5 = _mm_aesdeclast_si128(*b5, rk_last);
    if (num_blocks > 5)
        *b6 = _mm_aesdeclast_si128(*b6, rk_last);
    if (num_blocks > 6)
        *b7 = _mm_aesdeclast_si128(*b7, rk_last);
    if (num_blocks > 7)
        *b8 = _mm_aesdeclast_si128(*b8, rk_last);
}

static inline void aes_cbc_dec_blocks_128b(unsigned char *in, unsigned char *out,
                                           __m128i *chainblock,
                                           const __m128i *roundKeys,
                                           const int num_rounds, const uint32_t num_blocks) {

    if (num_blocks == 8) {
        __m128i d0 = _mm_loadu_si128((__m128i *) &in[0 * 16]);
        __m128i d1 = _mm_loadu_si128((__m128i *) &in[1 * 16]);
        __m128i d2 = _mm_loadu_si128((__m128i *) &in[2 * 16]);
        __m128i d3 = _mm_loadu_si128((__m128i *) &in[3 * 16]);
        __m128i d4 = _mm_loadu_si128((__m128i *) &in[4 * 16]);
        __m128i d5 = _mm_loadu_si128((__m128i *) &in[5 * 16]);
        __m128i d6 = _mm_loadu_si128((__m128i *) &in[6 * 16]);
        __m128i d7 = _mm_loadu_si128((__m128i *) &in[7 * 16]);

        const __m128i iv0 = *chainblock;
        const __m128i iv1 = d0;
        const __m128i iv2 = d1;
        const __m128i iv3 = d2;
        const __m128i iv4 = d3;
        const __m128i iv5 = d4;
        const __m128i iv6 = d5;
        const __m128i iv7 = d6;

        *chainblock = d7;

        aesdec_8_blocks_128b(&d0, &d1, &d2, &d3, &d4, &d5, &d6, &d7, roundKeys, num_rounds, 8);

        d0 = _mm_xor_si128(d0, iv0);
        d1 = _mm_xor_si128(d1, iv1);
        d2 = _mm_xor_si128(d2, iv2);
        d3 = _mm_xor_si128(d3, iv3);
        d4 = _mm_xor_si128(d4, iv4);
        d5 = _mm_xor_si128(d5, iv5);
        d6 = _mm_xor_si128(d6, iv6);
        d7 = _mm_xor_si128(d7, iv7);

        _mm_storeu_si128((__m128i *) &out[0 * 16], d0);
        _mm_storeu_si128((__m128i *) &out[1 * 16], d1);
        _mm_storeu_si128((__m128i *) &out[2 * 16], d2);
        _mm_storeu_si128((__m128i *) &out[3 * 16], d3);
        _mm_storeu_si128((__m128i *) &out[4 * 16], d4);
        _mm_storeu_si128((__m128i *) &out[5 * 16], d5);
        _mm_storeu_si128((__m128i *) &out[6 * 16], d6);
        _mm_storeu_si128((__m128i *) &out[7 * 16], d7);
    } else if (num_blocks == 7) {
        __m128i d0 = _mm_loadu_si128((__m128i *) &in[0 * 16]);
        __m128i d1 = _mm_loadu_si128((__m128i *) &in[1 * 16]);
        __m128i d2 = _mm_loadu_si128((__m128i *) &in[2 * 16]);
        __m128i d3 = _mm_loadu_si128((__m128i *) &in[3 * 16]);
        __m128i d4 = _mm_loadu_si128((__m128i *) &in[4 * 16]);
        __m128i d5 = _mm_loadu_si128((__m128i *) &in[5 * 16]);
        __m128i d6 = _mm_loadu_si128((__m128i *) &in[6 * 16]);

        const __m128i iv0 = *chainblock;
        const __m128i iv1 = d0;
        const __m128i iv2 = d1;
        const __m128i iv3 = d2;
        const __m128i iv4 = d3;
        const __m128i iv5 = d4;
        const __m128i iv6 = d5;

        *chainblock = d6;

        aesdec_8_blocks_128b(&d0, &d1, &d2, &d3, &d4, &d5, &d6, &d6, roundKeys, num_rounds, 7);

        d0 = _mm_xor_si128(d0, iv0);
        d1 = _mm_xor_si128(d1, iv1);
        d2 = _mm_xor_si128(d2, iv2);
        d3 = _mm_xor_si128(d3, iv3);
        d4 = _mm_xor_si128(d4, iv4);
        d5 = _mm_xor_si128(d5, iv5);
        d6 = _mm_xor_si128(d6, iv6);

        _mm_storeu_si128((__m128i *) &out[0 * 16], d0);
        _mm_storeu_si128((__m128i *) &out[1 * 16], d1);
        _mm_storeu_si128((__m128i *) &out[2 * 16], d2);
        _mm_storeu_si128((__m128i *) &out[3 * 16], d3);
        _mm_storeu_si128((__m128i *) &out[4 * 16], d4);
        _mm_storeu_si128((__m128i *) &out[5 * 16], d5);
        _mm_storeu_si128((__m128i *) &out[6 * 16], d6);
    } else if (num_blocks == 6) {
        __m128i d0 = _mm_loadu_si128((__m128i *) &in[0 * 16]);
        __m128i d1 = _mm_loadu_si128((__m128i *) &in[1 * 16]);
        __m128i d2 = _mm_loadu_si128((__m128i *) &in[2 * 16]);
        __m128i d3 = _mm_loadu_si128((__m128i *) &in[3 * 16]);
        __m128i d4 = _mm_loadu_si128((__m128i *) &in[4 * 16]);
        __m128i d5 = _mm_loadu_si128((__m128i *) &in[5 * 16]);

        const __m128i iv0 = *chainblock;
        const __m128i iv1 = d0;
        const __m128i iv2 = d1;
        const __m128i iv3 = d2;
        const __m128i iv4 = d3;
        const __m128i iv5 = d4;

        *chainblock = d5;

        aesdec_8_blocks_128b(&d0, &d1, &d2, &d3, &d4, &d5, &d5, &d5, roundKeys, num_rounds, 6);

        d0 = _mm_xor_si128(d0, iv0);
        d1 = _mm_xor_si128(d1, iv1);
        d2 = _mm_xor_si128(d2, iv2);
        d3 = _mm_xor_si128(d3, iv3);
        d4 = _mm_xor_si128(d4, iv4);
        d5 = _mm_xor_si128(d5, iv5);

        _mm_storeu_si128((__m128i *) &out[0 * 16], d0);
        _mm_storeu_si128((__m128i *) &out[1 * 16], d1);
        _mm_storeu_si128((__m128i *) &out[2 * 16], d2);
        _mm_storeu_si128((__m128i *) &out[3 * 16], d3);
        _mm_storeu_si128((__m128i *) &out[4 * 16], d4);
        _mm_storeu_si128((__m128i *) &out[5 * 16], d5);
    } else if (num_blocks == 5) {
        __m128i d0 = _mm_loadu_si128((__m128i *) &in[0 * 16]);
        __m128i d1 = _mm_loadu_si128((__m128i *) &in[1 * 16]);
        __m128i d2 = _mm_loadu_si128((__m128i *) &in[2 * 16]);
        __m128i d3 = _mm_loadu_si128((__m128i *) &in[3 * 16]);
        __m128i d4 = _mm_loadu_si128((__m128i *) &in[4 * 16]);

        const __m128i iv0 = *chainblock;
        const __m128i iv1 = d0;
        const __m128i iv2 = d1;
        const __m128i iv3 = d2;
        const __m128i iv4 = d3;

        *chainblock = d4;

        aesdec_8_blocks_128b(&d0, &d1, &d2, &d3, &d4, &d4, &d4, &d4, roundKeys, num_rounds, 5);

        d0 = _mm_xor_si128(d0, iv0);
        d1 = _mm_xor_si128(d1, iv1);
        d2 = _mm_xor_si128(d2, iv2);
        d3 = _mm_xor_si128(d3, iv3);
        d4 = _mm_xor_si128(d4, iv4);

        _mm_storeu_si128((__m128i *) &out[0 * 16], d0);
        _mm_storeu_si128((__m128i *) &out[1 * 16], d1);
        _mm_storeu_si128((__m128i *) &out[2 * 16], d2);
        _mm_storeu_si128((__m128i *) &out[3 * 16], d3);
        _mm_storeu_si128((__m128i *) &out[4 * 16], d4);
    } else if (num_blocks == 4) {
        __m128i d0 = _mm_loadu_si128((__m128i *) &in[0 * 16]);
        __m128i d1 = _mm_loadu_si128((__m128i *) &in[1 * 16]);
        __m128i d2 = _mm_loadu_si128((__m128i *) &in[2 * 16]);
        __m128i d3 = _mm_loadu_si128((__m128i *) &in[3 * 16]);

        const __m128i iv0 = *chainblock;
        const __m128i iv1 = d0;
        const __m128i iv2 = d1;
        const __m128i iv3 = d2;

        *chainblock = d3;

        aesdec_8_blocks_128b(&d0, &d1, &d2, &d3, &d3, &d3, &d3, &d3, roundKeys, num_rounds, 4);

        d0 = _mm_xor_si128(d0, iv0);
        d1 = _mm_xor_si128(d1, iv1);
        d2 = _mm_xor_si128(d2, iv2);
        d3 = _mm_xor_si128(d3, iv3);

        _mm_storeu_si128((__m128i *) &out[0 * 16], d0);
        _mm_storeu_si128((__m128i *) &out[1 * 16], d1);
        _mm_storeu_si128((__m128i *) &out[2 * 16], d2);
        _mm_storeu_si128((__m128i *) &out[3 * 16], d3);
    } else if (num_blocks == 3) {
        __m128i d0 = _mm_loadu_si128((__m128i *) &in[0 * 16]);
        __m128i d1 = _mm_loadu_si128((__m128i *) &in[1 * 16]);
        __m128i d2 = _mm_loadu_si128((__m128i *) &in[2 * 16]);

        const __m128i iv0 = *chainblock;
        const __m128i iv1 = d0;
        const __m128i iv2 = d1;

        *chainblock = d2;

        aesdec_8_blocks_128b(&d0, &d1, &d2, &d2, &d2, &d2, &d2, &d2, roundKeys, num_rounds, 3);

        d0 = _mm_xor_si128(d0, iv0);
        d1 = _mm_xor_si128(d1, iv1);
        d2 = _mm_xor_si128(d2, iv2);

        _mm_storeu_si128((__m128i *) &out[0 * 16], d0);
        _mm_storeu_si128((__m128i *) &out[1 * 16], d1);
        _mm_storeu_si128((__m128i *) &out[2 * 16], d2);
    } else if (num_blocks == 2) {
        __m128i d0 = _mm_loadu_si128((__m128i *) &in[0 * 16]);
        __m128i d1 = _mm_loadu_si128((__m128i *) &in[1 * 16]);

        const __m128i iv0 = *chainblock;
        const __m128i iv1 = d0;

        *chainblock = d1;

        aesdec_8_blocks_128b(&d0, &d1, &d1, &d1, &d1, &d1, &d1, &d1, roundKeys, num_rounds, 2);

        d0 = _mm_xor_si128(d0, iv0);
        d1 = _mm_xor_si128(d1, iv1);

        _mm_storeu_si128((__m128i *) &out[0 * 16], d0);
        _mm_storeu_si128((__m128i *) &out[1 * 16], d1);
    } else if (num_blocks == 1) {
        __m128i d0 = _mm_loadu_si128((__m128i *) &in[0 * 16]);

        const __m128i iv0 = *chainblock;

        *chainblock = d0;

        aesdec_8_blocks_128b(&d0, &d0, &d0, &d0, &d0, &d0, &d0, &d0, roundKeys, num_rounds, 1);

        d0 = _mm_xor_si128(d0, iv0);

        _mm_storeu_si128((__m128i *) &out[0 * 16], d0);
    }

}



size_t cbc_decrypt(cbc_ctx *cbc, unsigned char *src, uint32_t blocks, unsigned char *dest) {
    assert(cbc != NULL);
    unsigned char *destStart = dest;

    while (blocks >= 8) {
        aes_cbc_dec_blocks_128b(src, dest, &cbc->chainblock, cbc->roundKeys, cbc->num_rounds, 8);
        blocks -= 8;
        src += CBC_BLOCK_SIZE * 8;
        dest += CBC_BLOCK_SIZE * 8;
    }
    aes_cbc_dec_blocks_128b(src, dest, &cbc->chainblock, cbc->roundKeys, cbc->num_rounds, blocks);
    dest += blocks * CBC_BLOCK_SIZE;
    return (size_t) (dest - destStart);
}