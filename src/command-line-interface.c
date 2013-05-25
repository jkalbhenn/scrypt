#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "scrypt.h"
#include "base91/base91.c"
#include "util.c"

#define version "0.1"
#define program_name "scrypt"

int main (int argc, char **argv) {
  int opt;
  struct option longopts[7] = {
    {"inputfile", required_argument, NULL, 'i'},
    {"saltfile", required_argument, NULL, 's'},
    {"outputfile", required_argument, NULL, 'o'},
    {"ascii-input", no_argument, NULL, 'a'},
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'v'},
    {NULL, 0, NULL, 0}
  };
  while ((opt = getopt_long(argc, argv, "i:s:o:ahv", longopts, NULL)) != -1) {
    switch (opt) {
    case 'i':
    case 's':
    case 'o':
    case 'a':
    case 'v':
      printf("%s\n", version);
      return(0);
    case 'h':
      printf(
	"scrypt [options ...] password [salt size N r p]\n"
	"                     base91 [base91 integer integer integer integer]\n"
	"\noptions\n"
	"  -i|--inputfile path  read password in binary from file at path\n"
	"  -s|--saltfile path  read salt in binary from file at path\n"
	"  -o|--outputfile path  write the result string to file at path\n"
	"  -a|--ascii-input  password and salt arguments are ascii encoded\n"
	"  -h|--help  display this text and exit\n"
	"  -v|--version  output version information and exit\n\n");
      return(0);
    }
  }

  uint8_t* password = 0;
  uint8_t* salt = 0;
  size_t password_len = 0;
  size_t salt_len = 0;
  size_t size = 0;
  uint64_t N = 0;
  uint32_t r = 0;
  uint32_t p = 0;

  if (optind < argc) {
    password = malloc(strlen(argv[optind]));
    password_len = base91_decode(password, argv[optind], strlen(argv[optind]));
    optind += 1;
    if (optind < argc) {
      salt = malloc(strlen(argv[optind]));
      salt_len = base91_decode(salt, argv[optind], strlen(argv[optind]));
      optind += 1;
      if (optind < argc) {
	size = atol(argv[optind]); optind += 1;
	if (optind < argc) {
	  N = atol(argv[optind]); optind += 1;
	  if (optind < argc) {
	    r = atoi(argv[optind]); optind += 1;
	    if (optind < argc) { p = atoi(argv[optind]); }
	  }
	}
      }
    }
  }

  //printf("%s %s %lu %lu %d %d\n", password, salt, size, N, r, p);

  uint8_t* res;
  size_t res_len;
  scrypt_to_string(password, password_len, salt, salt_len, N, r, p, size, &res, &res_len);
  printf(res);
  printf("\n");
}
