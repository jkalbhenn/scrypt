/* scrypt-utility command-line interface.

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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "scrypt.h"
#include "base91/base91.c"
#include "shared.c"

#define version "0.1"
#define program_name "scrypt"

void display_help () {
  puts(
    "scrypt [options ...] password [salt size N r p salt-size]\n"
    "                     base91 [base91 integer integer integer integer integer]\n"
    "\noptions\n"
    //"  -i|--inputfile path  read password in binary from file at path\n"
    //"  -s|--saltfile path  read salt in binary from file at path\n"
    //"  -o|--outputfile path  write the result string to file at path\n"
    "  -c|--check hash  tests if hash is derived from a password\n"
    "  -a|--ascii-input  password and salt arguments are ascii encoded\n"
    "  -h|--help  display this text and exit\n"
    "  -v|--version  output version information and exit\n");
}

int main (int argc, char **argv) {
  int ascii_input_flag = 0;
  uint8_t* check_string = 0;
  int opt;
  struct option longopts[8] = {
    {"inputfile", required_argument, 0, 'i'},
    {"saltfile", required_argument, 0, 's'},
    {"outputfile", required_argument, 0, 'o'},
    {"ascii-input", no_argument, 0, 'a'},
    {"check", required_argument, 0, 'c'},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'v'},
    {0, 0, 0, 0}
  };
  while ((opt = getopt_long(argc, argv, "c:i:s:o:ahv", longopts, 0)) != -1) {
    switch (opt) {
    case 'v':
      printf("%s\n", version);
      return(0);
    case 'a': ascii_input_flag = 1; break;
    case 'c': check_string = optarg; break;
    case 'i':
    case 's':
    case 'o':
    case 'h':
      display_help();
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
    if (ascii_input_flag) {
      password = argv[optind];
      password_len = strlen(argv[optind]);
    }
    else {
      password = malloc(strlen(argv[optind]));
      password_len = base91_decode(password, argv[optind], strlen(argv[optind]));
    }
    optind += 1;
    if (!check_string && (optind < argc)) {
      if (*argv[optind] == '-') { salt = 0; salt_len = 0; }
      else if (ascii_input_flag) {
	salt = argv[optind];
	salt_len = strlen(argv[optind]);
      }
      else {
	salt = malloc(strlen(argv[optind]));
	salt_len = base91_decode(salt, argv[optind], strlen(argv[optind]));
      }
      optind += 1;
      if (optind < argc) {
	size = atol(argv[optind]); optind += 1;
	if (optind < argc) {
	  N = atol(argv[optind]); optind += 1;
	  if (optind < argc) {
	    r = atoi(argv[optind]); optind += 1;
	    if (optind < argc) {
	      p = atoi(argv[optind]); optind += 1;
	      if (!salt && (optind <= argc)) {
		salt_len = atoi(argv[optind]);
	      }
	    }
	  }
	}
      }
    }
  }
  else {
    puts("missing argument \"password\".\n");
    display_help();
    return(1);
  }

  uint8_t* res;
  size_t res_len;
  int status;
  if (check_string) {
    uint8_t* key;
    size_t key_len;
    status = scrypt_parse_string(check_string, strlen(check_string), &key, &key_len, &salt, &salt_len, &N, &r, &p);
    if (status) { return(status); }
#if verbose
    printf("salt %s, N %lu, r %d, p %d, key_len %lu, salt_len %lu\n", salt, N, r, p, key_len, salt_len);
#endif
    status = scrypt_to_string(password, password_len, salt, salt_len, N, r, p, key_len, &res, &res_len);
    if (status) { return(status); }
    puts((memcmp(res, check_string, res_len) == 0) ? "success" : "failure");
  }
  else {
    status = scrypt_to_string(password, password_len, salt, salt_len, N, r, p, size, &res, &res_len);
    if (status) { return(status); }
    puts(res);
  }
}
