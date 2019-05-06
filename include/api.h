#ifndef API_H
#define API_H

#include <stdlib.h>
#include <stdint.h>

#define Ch(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define Maj(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))
#define Sigma0(x) (((x) >> 2 | (x) << 30) ^ ((x) >> 13 | (x) << 19) ^ ((x) >> 22 | (x) << 10))
#define Sigma1(x) (((x) >> 6 | (x) << 26) ^ ((x) >> 11 | (x) << 21) ^ ((x) >> 25 | (x) << 7))
#define sigma0(x) (((x) >> 7 | (x) << 25) ^ ((x) >> 18 | (x) << 14) ^ ((x) >> 3))
#define sigma1(x) (((x) >> 17 | (x) << 15) ^ ((x) >> 19 | (x) << 13) ^ ((x) >> 10))

#define Round(a, b, c, d, e, f, g, h, k, w)				\
  do									\
    {									\
      uint32_t t1 = (h) + Sigma1(e) + Ch((e), (f), (g)) + (k) + (w);	\
      uint32_t t2 = Sigma0(a) + Maj((a), (b), (c));			\
      (d) += t1;							\
      (h) = t1 + t2;							\
    } while (0)

#ifdef WORDS_BIGENDIAN
#define BE32(x) (x)
#else
#define BE32(p) ((((p)&0xFF) << 24) | (((p)&0xFF00) << 8) | (((p)&0xFF0000) >> 8) | (((p)&0xFF000000) >> 24))
#endif

typedef struct
{
  uint32_t s[8];
  uint32_t buf[16]; /* In big endian */
  size_t bytes;
} secp256k1_sha256;

typedef struct
{
  uint64_t d[4];
} secp256k1_scalar;

#define SECP256K1_SCALAR_CONST(d7, d6, d5, d4, d3, d2, d1, d0)                                                                   \
  {                                                                                                                              \
    {                                                                                                                            \
      ((uint64_t)(d1)) << 32 | (d0), ((uint64_t)(d3)) << 32 | (d2), ((uint64_t)(d5)) << 32 | (d4), ((uint64_t)(d7)) << 32 | (d6) \
	}                                                                                                                            \
  }

int quick_test(unsigned char *input, unsigned int len);
int quick_sha256(unsigned char *input, unsigned int len, unsigned char *output);
int quick_sign();

#endif
