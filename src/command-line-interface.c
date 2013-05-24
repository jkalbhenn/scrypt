#include <stdio.h>
#include <getopt.h>
#include "scrypt.h"

#define version "0.1"
#define program_name "scrypt"

int main (int argc, char **argv) {
  int opt;
  struct option longopts[7] = {
    {"inputfile", no_argument, NULL, 'i'},
    {"saltfile", required_argument, NULL, 's'},
    {"outputfile", required_argument, NULL, 'o'},
    {"ascii-input", no_argument, NULL, 'a'},
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'v'},
    {NULL, 0, NULL, 0}
  };
  while ((opt = getopt_long(argc, argv, "i:s:o:ahv", longopts, NULL)) != -1) {
    switch (opt) {
    case 'd':
    case 'e':
    case 'm':
    case 'h':
      puts("%s [options ...] password [salt size N r p] "
	"  -i --inputfile"
	"  -i --saltfile"
	"  -o --outputfile"
	"  -a --ascii-input"
	"  -h --help  display this help and exit\n"
	"  -v --version  output version information and exit\n\n",
	program-name);
      return(0);
    case 'v':
      printf("%s", version);
      return(0);
    default:
      return(0);
    }

    return(0);
  }
}
