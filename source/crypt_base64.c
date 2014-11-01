/*-
 * Base64 encoding\decoding compatible with crypt.
 * Copyright 2013 Alexander Peslyak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

static const char * const itoa64 =
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static uint8_t * encode64_uint32(uint8_t * dst, size_t dstlen,
  uint32_t src, uint32_t srcbits)
{
  uint32_t bit;

  for (bit = 0; bit < srcbits; bit += 6) {
    if (dstlen < 1)
      return NULL;
    *dst++ = itoa64[src & 0x3f];
    dstlen--;
    src >>= 6;
  }

  return dst;
}

static uint8_t * encode64(uint8_t * dst, size_t dstlen,
  const uint8_t * src, size_t srclen)
{
  size_t i;

  for (i = 0; i < srclen; ) {
    uint8_t * dnext;
    uint32_t value = 0, bits = 0;
    do {
      value |= (uint32_t)src[i++] << bits;
      bits += 8;
    } while (bits < 24 && i < srclen);
    dnext = encode64_uint32(dst, dstlen, value, bits);
    if (!dnext)
      return NULL;
    dstlen -= dnext - dst;
    dst = dnext;
  }

  return dst;
}

static int decode64_one(uint32_t * dst, uint8_t src)
{
  const char * ptr = strchr(itoa64, src);
  if (ptr) {
    *dst = ptr - itoa64;
    return 0;
  }
  *dst = 0;
  return -1;
}

static const uint8_t * decode64_uint32(uint32_t * dst, uint32_t dstbits, const uint8_t * src)
{
  uint32_t bit;
  uint32_t value;

  value = 0;
  for (bit = 0; bit < dstbits; bit += 6) {
    uint32_t one;
    if (decode64_one(&one, *src)) {
      *dst = 0;
      return NULL;
    }
    src++;
    value |= one << bit;
  }

  *dst = value;
  return src;
}
