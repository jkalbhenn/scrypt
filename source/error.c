#define error_invalid_hash_format 2

uint8_t* scrypt_strerror (uint32_t n) {
  return(error_invalid_hash_format == n ? "invalid hash format" :
    "error without description");
}
