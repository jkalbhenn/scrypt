#define verbose 0
#define default_salt_length 16u
#define default_key_length 32u

static __thread struct basE91 b91;
#define number_length_b32(arg) (arg <= 0xff ? 1u : arg <= 0xffff ? 2u : arg <= 0xffffff ? 3u : 4u)
#define estimate_encoded_length_base91(size, salt_len, N, r, p) (size_t)ceil(2.3 * (double)(size + salt_len + number_length_b64(N) + number_length_b32(r) + number_length_b32(p)))
#define estimate_encoded_length_base64(size, salt_len, N, r, p) (size_t)ceil(3 * (double)(size + salt_len + number_length_b64(N) + number_length_b32(r) + number_length_b32(p)))
#define add_dash(buf, len) *(*buf + *len) = '-'; *len += 1;
#define add_dollar(buf, len) *buf = '$'; *len += 1;

#define number_length_b64(arg) (arg <= 0xff ? 1u : arg <= 0xffff ? 2u : arg <= 0xffffff ? 3u : arg <= 0xffffffff ? 4u : \
    arg <= 0xffffffffff ? 5u : arg <= 0xffffffffffff ? 6u : arg <= 0xffffffffffffff ? 7u : 8u)

#define base91_encode_concat(output, index, input, size) \
  basE91_init(&b91); \
  index += basE91_encode(&b91, input, size, output + index); \
  index += basE91_encode_end(&b91, output + index)

size_t base91_decode(uint8_t* output, uint8_t* input, size_t size) {
  basE91_init(&b91);
  size_t len = basE91_decode(&b91, input, size, output);
  return(len + basE91_decode_end(&b91, output + len));
}
