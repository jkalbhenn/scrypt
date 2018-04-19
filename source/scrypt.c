/* scrypt-utility library code.

   copyright 2013-2018 Julian Kalbhenn <jkal@posteo.eu>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "../foreign/crypt_base64.c"
#include "../foreign/base91/base91.c"
#include "crypto_scrypt.c"
#include "pickparams/pickparams.c"
#include "shared.c"

#define error_invalid_hash_format 2

int scrypt(const uint8_t * passwd, size_t passwdlen,
    const uint8_t * salt, size_t saltlen, uint64_t N, uint32_t _r, uint32_t _p,
    uint8_t * buf, size_t buflen) {
  crypto_scrypt(passwd, passwdlen, salt, saltlen, N, _r, _p, buf, buflen);
}

uint8_t* scrypt_strerror (uint32_t n) {
  return(error_invalid_hash_format == n ? "invalid hash format" :
    "error without description");
}

uint32_t random_string (uint8_t** salt, size_t salt_len) {
  *salt = malloc(salt_len);
  FILE* file = fopen("/dev/urandom", "r"); if (!file) { return(1); }
  size_t len = fread(*salt, salt_len, 1, file);
  if (!len) { return(1); }
  fclose(file); return (0);
}

uint32_t scrypt_set_defaults (uint8_t** salt, size_t* salt_len, size_t* size, uint64_t* N, uint32_t* r, uint32_t* p) {
  uint32_t status;
  if (!(*N && *r && *p)) {
    int logN;
    uint32_t default_r;
    uint32_t default_p;
    status = pickparams(0, 0.5, 3.0, &logN, &default_r, &default_p, 0); if (status) { return(status); }
    if (!*N) { *N = (uint64_t)(1) << logN; }
    if (!*r) { *r = default_r; }
    if (!*p) { *p = default_p; }
  }
  if (!*salt) {
    if (!*salt_len) { *salt_len = default_salt_length; }
    status = random_string(salt, *salt_len);
    if (status) { return(status); }
  }
  if (!*size) { *size = default_key_length; }
  return(0);
}

uint32_t scrypt_parse_string_base91 (uint8_t* arg, size_t arg_len, uint8_t** key, size_t* key_len, uint8_t** salt, size_t* salt_len, uint64_t* N, uint32_t* r, uint32_t* p) {
  size_t index = 0;
  uint8_t count = 0;
  size_t previous_index = 0;
  uint32_t logN = 0;
  while (index < arg_len) {
    if (*(arg + index) == '-') {
      count += 1;
      switch (count) {
      case 1:
	previous_index = index;
	*key = malloc(index); if (!*key) { return(1); }
	*key_len = base91_decode(*key, arg, index);
      case 2:
	*salt = malloc(index - previous_index); if (!*salt) { return(1); }
	*salt_len = base91_decode(*salt, arg + previous_index, index - previous_index);
	previous_index = index;
      case 3:
	base91_decode((uint8_t*)&logN, arg + previous_index, index - previous_index);
	*N = (uint64_t)(1) << logN;
	previous_index = index;
      case 4:
	*r = 0;
	base91_decode((uint8_t*)r, arg + previous_index, index - previous_index);
	previous_index = index;
      }
    }
    index += 1;
  }
  *p = 0;
  base91_decode((uint8_t*)p, arg + previous_index, index - previous_index);
  return(0);
}

uint32_t scrypt_to_string_base91 (
  uint8_t* password, size_t password_len, uint8_t* salt, size_t salt_len,
  uint64_t N, uint32_t r, uint32_t p, size_t size, uint8_t** res, size_t* res_len)
{
  uint32_t status;
  status = scrypt_set_defaults(&salt, &salt_len, &size, &N, &r, &p);
#if verbose
  printf("with defaults: N %lu, r %d, p %d, key_len %lu, salt_len %lu\n", N, r, p, size, salt_len);
#endif
  if (status) { return(status); }
  uint8_t* derived_key = malloc(size); if (!derived_key) { return(1); }
  status = crypto_scrypt(password, password_len, salt, salt_len, N, r, p, derived_key, size);
  if (status) { return(status); }
  uint32_t logN = (uint32_t)log2f(N);
  *res = (uint8_t*)malloc(estimate_encoded_length_base91(size, salt_len, N, r, p));
  if (!*res) { return(1); }
  *res_len = 0;
  base91_encode_concat(*res, *res_len, derived_key, size);
  add_dash(res, res_len);
  base91_encode_concat(*res, *res_len, salt, salt_len);
  add_dash(res, res_len);
  base91_encode_concat(*res, *res_len, &logN, number_length_b64(logN));
  add_dash(res, res_len);
  base91_encode_concat(*res, *res_len, &r, number_length_b32(r));
  add_dash(res, res_len);
  base91_encode_concat(*res, *res_len, &p, number_length_b32(p));
  *(*res + *res_len) = 0;
  return(0);
}

uint32_t scrypt_parse_string_crypt (const uint8_t* arg, size_t arg_len, uint8_t** salt, size_t* salt_len, uint64_t* N, uint32_t* r, uint32_t* p) {
  if (!((arg[0] == '$') && (arg[1] == '7') && (arg[2] == '$'))) {
    return(error_invalid_hash_format);
  }
  uint32_t logN = 0;
  size_t index = arg_len;
  // crypt format-identifier (3 chars) + parameters (11 chars) + salt (non-limited size) + password (43 chars)
  while (index >= 14) {
    if (*(arg + index) == '$') {
      *salt_len = index - 14;
      *salt = malloc(*salt_len); if (!*salt) { return(1); }
      memcpy(*salt, arg + 14, *salt_len);
      if (decode64_one(&logN, *(arg + 3))) { return(1); }
      *N = (uint64_t)(1) << logN;
      decode64_uint32(r, 30, arg + 4);
      decode64_uint32(p, 30, arg + 9);
    }
    index -= 1;
  }
  return(0);
}

uint32_t scrypt_to_string_crypt (
  uint8_t* password, size_t password_len, uint8_t* salt, size_t salt_len,
  uint64_t N, uint32_t r, uint32_t p, uint8_t** res, size_t* res_len)
{
  uint32_t status;
  size_t key_len = 32;
  uint8_t use_default_salt = salt == 0;
  status = scrypt_set_defaults(&salt, &salt_len, &key_len, &N, &r, &p);
  if (status) { return(status); }
  if (use_default_salt) {
    // base64-encode the random bytes generated for the salt
    uint8_t* salt_base64 = malloc(salt_len); if (!salt_base64) { return(1); }
    encode64(salt_base64, salt_len, salt, salt_len);
    free(salt);
    salt = salt_base64;
  }
  uint8_t* derived_key = malloc(key_len); if (!derived_key) { return(1); }
  status = crypto_scrypt(password, password_len, salt, salt_len, N, r, p, derived_key, key_len);
  if (status) { return(status); }
  uint32_t logN = (uint32_t)log2f(N);
  size_t estimated_len = estimate_encoded_length_base64(key_len, salt_len, N, r, p);
  uint8_t* res_p;
  *res = (uint8_t*)malloc(estimated_len);
  if (!*res) { return(1); }
  memcpy(*res, "$7$", 3);
  res_p = *res + 3;
  *res_p = itoa64[logN];
  res_p = encode64_uint32(res_p + 1, estimated_len - (res_p - *res), r, 30);
  res_p = encode64_uint32(res_p, estimated_len - (res_p - *res), p, 30);
  memcpy(res_p, salt, salt_len);
  res_p += salt_len;
  *res_p = '$';
  res_p = encode64(res_p + 1, estimated_len - (res_p - *res), derived_key, key_len);
  *res_p = 0;
  *res_len = (res_p + 1) - *res;
  return(0);
}
