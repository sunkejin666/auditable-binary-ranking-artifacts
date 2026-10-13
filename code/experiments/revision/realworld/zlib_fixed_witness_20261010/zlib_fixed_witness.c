#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zlib.h"

static uint32_t step(uint32_t *s) {
    uint32_t x = *s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *s = x;
    return x;
}

static void fill_input(unsigned char *p, size_t n, unsigned mode, uint32_t seed) {
    size_t i;
    uint32_t s = seed ? seed : 1u;
    if (mode == 0) {
        for (i = 0; i < n; ++i) p[i] = (unsigned char)step(&s);
    } else if (mode == 1) {
        for (i = 0; i < n; ++i) p[i] = (unsigned char)(i & 0xffu);
    } else if (mode == 2) {
        for (i = 0; i < n; ++i) p[i] = (unsigned char)((i / 257u) & 0xffu);
    } else if (mode == 3) {
        for (i = 0; i < n; ++i) p[i] = (unsigned char)((i * 17u + (i / 31u)) & 0xffu);
        for (i = 257; i < n; i += 911) p[i] ^= (unsigned char)(step(&s) | 1u);
    } else if (mode == 4) {
        size_t half = n > 32768 ? 32768 : n / 2;
        for (i = 0; i < half; ++i) p[i] = (unsigned char)step(&s);
        for (i = half; i < n; ++i) p[i] = p[(i - half) % half];
    } else if (mode == 5) {
        for (i = 0; i < n; ++i) {
            size_t q = i % 4096;
            p[i] = (unsigned char)((q * 29u + q / 7u) & 0xffu);
            if ((i % 4096) == 2047) p[i] ^= (unsigned char)(step(&s) | 1u);
        }
    } else {
        for (i = 0; i < n; ++i) p[i] = (unsigned char)(step(&s) ^ (uint32_t)(i * 131u));
    }
}

static int run_case(size_t n, unsigned mode, uint32_t seed, int level,
                    int mem_level, int window_bits, unsigned chunk, int flush_each) {
    unsigned char *input = (unsigned char *)malloc(n ? n : 1);
    unsigned char output[4096];
    z_stream zs;
    size_t off = 0;
    int ret, done = 0;
    if (!input) return 2;
    fill_input(input, n, mode, seed);
    memset(&zs, 0, sizeof(zs));
    ret = deflateInit2(&zs, level, Z_DEFLATED, window_bits, mem_level, Z_FIXED);
    if (ret != Z_OK) { free(input); return 3; }
    while (!done) {
        size_t take = off < n ? n - off : 0;
        if (take > chunk) take = chunk;
        zs.next_in = input + off;
        zs.avail_in = (uInt)take;
        off += take;
        do {
            zs.next_out = output;
            zs.avail_out = (uInt)sizeof(output);
            ret = deflate(&zs, off >= n ? Z_FINISH : (flush_each ? Z_SYNC_FLUSH : Z_NO_FLUSH));
            if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) {
                deflateEnd(&zs); free(input); return 4;
            }
            if (ret == Z_STREAM_END) done = 1;
        } while (zs.avail_in != 0 || zs.avail_out == 0 || (off >= n && !done));
        if (off >= n && ret == Z_BUF_ERROR && zs.avail_in == 0) {
            /* A bounded retry prevents a malformed library from spinning forever. */
            zs.next_out = output;
            zs.avail_out = (uInt)sizeof(output);
            ret = deflate(&zs, Z_FINISH);
            if (ret == Z_STREAM_END) done = 1;
            else if (ret != Z_OK && ret != Z_BUF_ERROR) {
                deflateEnd(&zs); free(input); return 5;
            }
        }
    }
    ret = deflateEnd(&zs);
    free(input);
    return ret == Z_OK ? 0 : 6;
}

int main(int argc, char **argv) {
    size_t n = argc > 1 ? (size_t)strtoull(argv[1], NULL, 10) : 262144;
    unsigned mode = argc > 2 ? (unsigned)strtoul(argv[2], NULL, 10) : 0;
    uint32_t seed = argc > 3 ? (uint32_t)strtoul(argv[3], NULL, 10) : 1;
    int level = argc > 4 ? atoi(argv[4]) : Z_DEFAULT_COMPRESSION;
    int mem_level = argc > 5 ? atoi(argv[5]) : 8;
    int window_bits = argc > 6 ? atoi(argv[6]) : 15;
    unsigned chunk = argc > 7 ? (unsigned)strtoul(argv[7], NULL, 10) : 16384;
    int flush_each = argc > 8 ? atoi(argv[8]) : 0;
    int rc = run_case(n, mode, seed, level, mem_level, window_bits, chunk, flush_each);
    printf("n=%zu mode=%u seed=%u level=%d mem=%d window=%d chunk=%u flush=%d rc=%d\n",
           n, mode, seed, level, mem_level, window_bits, chunk, flush_each, rc);
    return rc;
}
