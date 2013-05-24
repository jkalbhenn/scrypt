#include <sys/time.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include "memlimit.c"
#include "scrypt/scrypt.c"
#include "base91/base91.c"

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
      if ((uint64_t)(1) << *logN > maxN / 2)
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

static int getsalt(uint8_t salt[32]) {
  int fd;
  ssize_t lenread;
  uint8_t * buf = salt;
  size_t buflen = 32;
  /* Open /dev/urandom. */
  if ((fd = open("/dev/urandom", O_RDONLY)) == -1) { goto err0; }

  /* Read bytes until we have filled the buffer. */
  while (buflen > 0) {
    if ((lenread = read(fd, buf, buflen)) == -1) { goto err1; }

    /* The random device should never EOF. */
    if (lenread == 0) { goto err1; }

    /* We're partly done. */
    buf += lenread;
    buflen -= lenread;
  }

  while (close(fd) == -1) {
    if (errno != EINTR) { goto err0; }
  }
  return (0);
err1:
  close(fd);
err0:
  return (4);
}

#define default_salt_length 8
#define default_key_length 16

int set_defaults (uint8_t** salt, size_t* salt_len, size_t* size, uint64_t* N, uint32_t* r, uint32_t* p) {
  int status;
  if (!(*N && *r && *p)) {
    int logN;
    uint32_t default_r;
    uint32_t default_p;
    status = pickparams(0, 0.5, 2.0, &logN, &default_r, &default_p); if (status) { return(status); }
    if (!*N) { *N = (uint64_t)(1) << logN; }
    if (!*r) { *r = default_r; }
    if (!*p) { *p = default_p; }
  }
  if (!*salt) {
    uint8_t default_salt[default_salt_length];
    status = getsalt(default_salt);
    if (status) { return(status); }
    *salt = default_salt;
    *salt_len = default_salt_length;
  }
  if (!*size) { *size = default_key_length; }
  return(0);
}

static struct basE91 b91;

#define base91_encode_concat(output, index, input, size) \
  basE91_init(&b91); \
  index += basE91_encode(&b91, input, size, output + index); \
  index += basE91_encode_end(&b91, output + index)

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

#define add_dash(buf, len) *(*buf + *len) = '-'; *len += 1;

int scrypt_to_string (
  uint8_t* password, size_t password_len, uint8_t* salt, size_t salt_len,
  uint64_t N, uint32_t r, uint32_t p, size_t size, uint8_t** res, size_t* res_len)
{
  int status;
  status = set_defaults(&salt, &salt_len, &size, &N, &r, &p);
  uint8_t* derived_key = malloc(size); if (!derived_key) { exit(1); }
  status = scrypt(password, password_len, salt, salt_len, N, r, p, derived_key, size);
  if (status) { printf("error"); exit(status); }
  *res = (uint8_t*)malloc((3 * (size + strlen(salt) + sizeof(N) + sizeof(r) + sizeof(p))) + 1);
  base91_encode_concat(*res, *res_len, derived_key, size);
  add_dash(res, res_len);
  base91_encode_concat(*res, *res_len, salt, salt_len);
  add_dash(res, res_len);
  base91_encode_concat(*res, *res_len, &N, sizeof(N));
  add_dash(res, res_len);
  base91_encode_concat(*res, *res_len, &r, sizeof(r));
  add_dash(res, res_len);
  base91_encode_concat(*res, *res_len, &p, sizeof(p));
  *(*res + *res_len) = 0;
  return(0);
}
