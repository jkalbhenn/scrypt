A library and command-line utility for creating scrypt password key derivations. The programming language used is C.

# Status
Should work on linux and all four reference tests of the [scrypt IETF draft](http://tools.ietf.org/id/draft-josefsson-scrypt-kdf-01.txt) pass successfully.

# Installation
## Installation requirements
The provided compile script uses shell and "gcc", and the code depends on the C standard library, "glibc" for example. All other dependencies are included.

## Compilation and installation
```
./exe/compile && ./exe/install [target-prefix]
```

* Installs a library under {target-prefix}/usr/lib/libscrypt.so
* Installs a header file under {target-prefix}/usr/include/scrypt.h
* Installs a binary under {target-prefix}/usr/bin/scrypt-kdf

# Command-line interface
```
scrypt-kdf [options ...] password [salt N r p size salt-size]
                         string string integer integer integer integer integer]
options
  -b|--base91-input  password and salt arguments are base91 encoded
  -c|--check hash  test if hash is derived from a password
  -h|--help  display this text and exit
  -p|--crypt  use unix crypt format
  -v|--version  output version information and exit
```

* Defaults for a parameter are used with the minus character -
* "size" and "salt-size" are only used if password or salt are left out or set to "-". They specify a number of bits and must be divisible by 8

## Examples
Create a hash with random salt from /dev/urandom and estimated cost values:
```
scrypt-kdf testpassword
```

Custom values for salt and other parameters:
```
scrypt-kdf testpassword testsalt 16384 8 1 256
```

Testing if a hash corresponds to a password:
```
scrypt-kdf testpassword -c 'qgr]R7~eLs(?Q2$T"*)P%xYbqQq(!PDT@hL|;L7D-fPNKS[7*qU-OA-IA-BA'
success
```

Always use single quotes around base91 hashes on the command-line, since the hash might contain special characters that are interpreted by the shell, even inside double quotes.

Using a 128 bit key with a 64 bit random salt and defaults for other parameters:
```
scrypt-kdf testpassword - - - - - 128 64
```

# Output format
## Current default
* Base91 encoded field values
* Delimited by -
* Order: key salt logN r p

Example
```
qgr]R7~eLs(?Q2$T"*)P%xYbqQq(!PDT@hL|;L7D-fPNKS[7*qU-OA-IA-BA
```
## Unix crypt
* Crypt-base64 encoded key
* Delimited by $
* Order: format-id logN r p salt key

Example
```
$7$C6..../....testsalt$8iWefERUpfDgs0B1s2CCn0flMHOLqzCNVMn0AwxoEM8
```

# Defaults
* Key length 256
* Salt length 128
* Salt read from /dev/urandom
* (N r p) parameters estimated by checking cpuspeed and free memory

# Structure
```
libscrypt
  scrypt
  scrypt_parse_string
  scrypt_set_defaults
  scrypt_to_string
  scrypt_strerror
scrypt
```

# Programming interface
## Usage
* When using C, "#include <scrypt.h>"
* Setup linking with "libscrypt"

## scrypt
The fundamental scrypt key derivation function.

```
int scrypt (
  const uint8_t * password, size_t password_len, const uint8_t * salt, size_t salt_len,
  uint64_t N, uint32_t r, uint32_t p, uint8_t * res, size_t res_len);
```

* N must be a power of 2
* r * p < 2^30
* res_len <= (2^32 - 1)

## scrypt_to_string
Creates a hash string like the command-line utility.

```
uint32_t scrypt_to_string_base91 (
  uint8_t* password, size_t password_len, uint8_t* salt, size_t salt_len,
  uint64_t N, uint32_t r, uint32_t p, size_t size, uint8_t** res, size_t* res_len);
```

```
uint32_t scrypt_to_string_crypt (
  uint8_t* password, size_t password_len, uint8_t* salt, size_t salt_len,
  uint64_t N, uint32_t r, uint32_t p, uint8_t** res, size_t* res_len);
```

## Example call
```
uint8_t* res;
size_t res_len;
int status;
uint8_t* password = 0;
uint8_t* salt = 0;
size_t password_len = 0;
size_t salt_len = 0;
size_t size = 0;
uint64_t N = 0;
uint32_t r = 0;
uint32_t p = 0;

status = scrypt_to_string_base91(password, password_len, salt, salt_len, N, r, p, size, &res, &res_len);
```

## scrypt_parse_string
```
int scrypt_parse_string_base91 (uint8_t* arg, size_t arg_len, uint8_t** key, size_t* key_len, uint8_t** salt, size_t* salt_len, uint64_t* N, uint32_t* r, uint32_t* p);
```
```
int scrypt_parse_string_crypt (uint8_t* arg, size_t arg_len, uint8_t** salt, size_t* salt_len, uint64_t* N, uint32_t* r, uint32_t* p);
```

## Example call
Variable initialisations implied, see above.
```
status = scrypt_parse_string_base91(check_string, strlen(check_string), &key, &key_len, &salt, &salt_len, &N, &r, &p);
```

## scrypt_set_defaults
```
int scrypt_set_defaults (uint8_t** salt, size_t* salt_len, size_t* size, uint64_t* N, uint32_t* r, uint32_t* p);
```

Variables with the value of zero are updated with defaults.

## Example call
```
status = scrypt_set_defaults(&salt, &salt_len, &size, &N, &r, &p);
```

# Sources
Uses code from the "scrypt" file encryption utility written by C. Percival and the scrypt algorithm by the same author, a unix crypt compatible base64 implementation by Alexander Peslyak, and the base91 implementation by Joachim Henke.

# License
* [Base91 implementation](http://base91.sourceforge.net/) - version 0.6.0 - bsd 3-clause
* [Scrypt implementation and utility code](http://www.tarsnap.com/scrypt.html) - version 1.2.0 - bsd 2-clause
* Base64 implementation - custom, see source file "crypt_base64.c"
* Rest - lgpl3+

# Rationale
## Field order
* When creating the string, it might seem more intuitive to start with the parameters, salt and password, but when reading the string the reverse order seems better.
One may think of it like this: the user wants to create a key derivation, and the first and most prominent thing they get in the result is the actual key derivation, then the parameters at the end. In that sense it is in order of most significant to least significant when reading from left to right
* Key and salt have a more predictable length than the other parts, which are more dependent on environment state
* A program using the library may only be interested in the the key, while keeping track of the parameters somewhere else. It should then be easier to extract the key from the beginning

## Field separator
* Don't use a cryptic symbol if a less cryptic and more common symbol does the job, for example with preferring "-" over "$"
* Base91 leaves "-" for use

## Base91
* Enables the use of the full binary range for specifying a password and salt on the command-line, not just the ascii character range, because it is an encoding
* Result strings are shorter than they would be with base64
* Base91 seems reasonably well defined - efficient because it uses nearly all of asciis 94 printable characters, and leaving three useful characters out of the set "-", "'" "\"
* The base91 encoding is a bit more straightforward because it has only one standard definition, and not multiple historical variants (padding et cetera) like base64
* It is not compatible with the format used in the /etc/passwd file because it uses ":". Base64 can be used in that case

Possible enhancements
* User testing
* Improved command-line interface
* Portability
* More input/output options

# External links
* http://base91.sourceforge.net/
* http://tools.ietf.org/id/draft-josefsson-scrypt-kdf-01.txt
* http://www.tarsnap.com/scrypt.html
* http://code.google.com/p/scrypt/
* https://www.gitorious.org/scrypt/scrypt-unix-crypt/blobs/raw/master/unix-scrypt.txt

## A few interesting scrypt projects
* http://git.chromium.org/gitweb/?p=chromiumos/third_party/libscrypt.git;a=summary
* https://github.com/scintill/scrypt
* https://pypi.python.org/pypi/scrypt/
* https://github.com/barrysteyn/node-scrypt
* https://github.com/pbhogan/scrypt
* https://github.com/viking/scrypty
