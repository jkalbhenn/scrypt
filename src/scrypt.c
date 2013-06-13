/*-
 * This file contains code under the following license terms (up to line 300):
 *
 * Copyright 2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */
#include <sys/time.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include "memlimit.c"
#include "scrypt/scrypt.c"
#include "base91/base91.c"
#include "crypt_base64.c"

#ifdef HAVE_CLOCK_GETTIME

static clock_t clocktouse;

static int
getclockres(double * resd)
{
  struct timespec res;

  /*
   * Try clocks in order of preference until we find one which works.
   * (We assume that if clock_getres works, clock_gettime will, too.)
   * The use of if/else/if/else/if/else rather than if/elif/elif/else
   * is ugly but legal, and allows us to #ifdef things appropriately.
   */
#ifdef CLOCK_VIRTUAL
  if (clock_getres(CLOCK_VIRTUAL, &res) == 0)
    clocktouse = CLOCK_VIRTUAL;
  else
#endif
#ifdef CLOCK_MONOTONIC
    if (clock_getres(CLOCK_MONOTONIC, &res) == 0)
      clocktouse = CLOCK_MONOTONIC;
    else
#endif
      if (clock_getres(CLOCK_REALTIME, &res) == 0)
	clocktouse = CLOCK_REALTIME;
      else
	return (-1);

  /* Convert clock resolution to a double. */
  *resd = res.tv_sec + res.tv_nsec * 0.000000001;

  return (0);
}

static int
getclocktime(struct timespec * ts)
{

  if (clock_gettime(clocktouse, ts))
    return (-1);

  return (0);
}

#else
static int
getclockres(double * resd)
{

  *resd = 1.0 / CLOCKS_PER_SEC;

  return (0);
}

static int
getclocktime(struct timespec * ts)
{
  struct timeval tv;

  if (gettimeofday(&tv, NULL))
    return (-1);
  ts->tv_sec = tv.tv_sec;
  ts->tv_nsec = tv.tv_usec * 1000;

  return (0);
}
#endif

static int
getclockdiff(struct timespec * st, double * diffd)
{
  struct timespec en;

  if (getclocktime(&en))
    return (1);
  *diffd = (en.tv_nsec - st->tv_nsec) * 0.000000001 +
    (en.tv_sec - st->tv_sec);

  return (0);
}

/**
 * cpuperf(opps):
 * Estimate the number of salsa20/8 cores which can be executed per second,
 * and return the value via opps.
 */
int
cpuperf(double * opps)
{
  struct timespec st;
  double resd, diffd;
  uint64_t i = 0;

  /* Get the clock resolution. */
  if (getclockres(&resd))
    return (2);

#ifdef DEBUG
  fprintf(stderr, "Clock resolution is %f\n", resd);
#endif

  /* Loop until the clock ticks. */
  if (getclocktime(&st))
    return (2);
  do {
    /* Do an scrypt. */
    if (scrypt(NULL, 0, NULL, 0, 16, 1, 1, NULL, 0))
      return (3);

    /* Has the clock ticked? */
    if (getclockdiff(&st, &diffd))
      return (2);
    if (diffd > 0)
      break;
  } while (1);

  /* Count how many scrypts we can do before the next tick. */
  if (getclocktime(&st))
    return (2);
  do {
    /* Do an scrypt. */
    if (scrypt(NULL, 0, NULL, 0, 128, 1, 1, NULL, 0))
      return (3);

    /* We invoked the salsa20/8 core 512 times. */
    i += 512;

    /* Check if we have looped for long enough. */
    if (getclockdiff(&st, &diffd))
      return (2);
    if (diffd > resd)
      break;
  } while (1);

#ifdef DEBUG
  fprintf(stderr, "%ju salsa20/8 cores performed in %f seconds\n",
    (uintmax_t)i, diffd);
#endif

  /* We can do approximately i salsa20/8 cores per diffd seconds. */
  *opps = i / diffd;
  return (0);
}

static int
pickparams(size_t maxmem, double maxmemfrac, double maxtime,
  int * logN, uint32_t * r, uint32_t * p)
{
  size_t memlimit;
  double opps;
  double opslimit;
  double maxN, maxrp;
  int rc;

  /* Figure out how much memory to use. */
  if (memtouse(maxmem, maxmemfrac, &memlimit))
    return (1);

  /* Figure out how fast the CPU is. */
  if ((rc = cpuperf(&opps)) != 0)
    return (rc);
  opslimit = opps * maxtime;

  /* Allow a minimum of 2^15 salsa20/8 cores. */
  if (opslimit < 32768)
    opslimit = 32768;

  /* Fix r = 8 for now. */
  *r = 8;

  /*
   * The memory limit requires that 128Nr <= memlimit, while the CPU
   * limit requires that 4Nrp <= opslimit.  If opslimit < memlimit/32,
   * opslimit imposes the stronger limit on N.
   */
#ifdef DEBUG
  fprintf(stderr, "Requiring 128Nr <= %zu, 4Nrp <= %f\n",
    memlimit, opslimit);
#endif
  if (opslimit < memlimit/32) {
    /* Set p = 1 and choose N based on the CPU limit. */
    *p = 1;
    maxN = opslimit / (*r * 4);
    for (*logN = 1; *logN < 63; *logN += 1) {
      if (((uint64_t)(1) << *logN) > (maxN / 2))
	break;
    }
  } else {
    /* Set N based on the memory limit. */
    maxN = memlimit / (*r * 128);
    for (*logN = 1; *logN < 63; *logN += 1) {
      if ((uint64_t)(1) << *logN > maxN / 2)
	break;
    }

    /* Choose p based on the CPU limit. */
    maxrp = (opslimit / 4) / ((uint64_t)(1) << *logN);
    if (maxrp > 0x3fffffff)
      maxrp = 0x3fffffff;
    *p = (uint32_t)(maxrp) / *r;
  }

#ifdef DEBUG
  fprintf(stderr, "N = %zu r = %d p = %d\n",
    (size_t)(1) << *logN, (int)(*r), (int)(*p));
#endif

  /* Success! */
  return (0);
}

#include <math.h>
#include "shared.c"

uint8_t* scrypt_strerror (int number) {
  switch (number) {
  case 1:
    return("Error determining amount of available memory");
  case 2:
    return("Error reading clocks");
  case 3:
    return("Error computing derived key");
  case 4:
    return("Error reading salt");
  case 5:
    return("OpenSSL error");
  case 6:
    return("Error allocating memory");
  case 7:
    return("Input is not valid scrypt-encrypted block");
  case 8:
    return("Unrecognized scrypt format version");
  case 9:
    return("Decrypting file would require too much memory");
  case 10:
    return("Decrypting file would take too much CPU time");
  case 11:
    return("Passphrase is incorrect");
  case 12:
    return("Error writing file");
  case 13:
    return("Error reading file");
  }
}

/* scrypt-utility library code.

   copyright 2013 Julian Kalbhenn <jkal@posteo.eu>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
int random_string (uint8_t** salt, size_t salt_len) {
  *salt = malloc(salt_len);
  FILE* file = fopen("/dev/urandom", "r"); if (!file) { return(1); }
  size_t len = fread(*salt, salt_len, 1, file);
  if (!len) { return(1); }
  fclose(file); return (0);
}

int scrypt_set_defaults (uint8_t** salt, size_t* salt_len, size_t* size, uint64_t* N, uint32_t* r, uint32_t* p) {
  int status;
  if (!(*N && *r && *p)) {
    int logN;
    uint32_t default_r;
    uint32_t default_p;
    status = pickparams(0, 0.5, 3.0, &logN, &default_r, &default_p); if (status) { return(status); }
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

int scrypt_parse_string_base91 (uint8_t* arg, size_t arg_len, uint8_t** key, size_t* key_len, uint8_t** salt, size_t* salt_len, uint64_t* N, uint32_t* r, uint32_t* p) {
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

int scrypt_to_string_base91 (
  uint8_t* password, size_t password_len, uint8_t* salt, size_t salt_len,
  uint64_t N, uint32_t r, uint32_t p, size_t size, uint8_t** res, size_t* res_len)
{
  int status;
  status = scrypt_set_defaults(&salt, &salt_len, &size, &N, &r, &p);
#if verbose
  printf("with defaults: N %lu, r %d, p %d, key_len %lu, salt_len %lu\n", N, r, p, size, salt_len);
#endif
  if (status) { return(status); }
  uint8_t* derived_key = malloc(size); if (!derived_key) { return(1); }
  status = scrypt(password, password_len, salt, salt_len, N, r, p, derived_key, size);
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

int scrypt_parse_string_crypt (uint8_t* arg, size_t arg_len, uint8_t** key, size_t* key_len, uint8_t** salt, size_t* salt_len, uint64_t* N, uint32_t* r, uint32_t* p) {
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

int scrypt_to_string_crypt (
  uint8_t* password, size_t password_len, uint8_t* salt, size_t salt_len,
  uint64_t N, uint32_t r, uint32_t p, size_t size, uint8_t** res, size_t* res_len)
{
  int status;
  status = scrypt_set_defaults(&salt, &salt_len, &size, &N, &r, &p);
#if verbose
  printf("with defaults: N %lu, r %d, p %d, key_len %lu, salt_len %lu\n", N, r, p, size, salt_len);
#endif
  if (status) { return(status); }
  uint8_t* derived_key = malloc(size); if (!derived_key) { return(1); }
  status = scrypt(password, password_len, salt, salt_len, N, r, p, derived_key, size);
  if (status) { return(status); }
  uint32_t logN = (uint32_t)log2f(N);
  size_t encoded_length = estimate_encoded_length_base64(size, salt_len, N, r, p);
  uint8_t* res_p;
  *res = (uint8_t*)malloc(encoded_length);
  if (!*res) { return(1); }
  *res_len = 0;
  memcpy(*res, "$7$", 3); encoded_length -= 3;
  res_p = encode64(*res, encoded_length, derived_key, size);
  add_dollar(res_p, res_len);
  res_p = encode64(res_p, encoded_length - (res_p - *res), salt, salt_len);
  add_dollar(res_p, res_len);
  *res_p = 0;
  return(0);
}
