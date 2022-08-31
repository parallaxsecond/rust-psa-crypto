all: psa-xtensa

psa-xtensa: patch-config-xtensa patch-entropy-poll patch-x509-crt patch-cipher-info-from-string-xtensa patch-rsa patch-fclose
	make -j CC=$(XTENSA_GCC) CFLAGS="-O2 -DMBEDTLS_USE_PSA_CRYPTO=1" lib

CONFIG_H_FILE := include/mbedtls/mbedtls_config.h
patch-config-xtensa:
	sed -i -E 's/^(#define MBEDTLS_NET_C)/\/\/\0/g' $(CONFIG_H_FILE)
	sed -i -E 's/^(#define MBEDTLS_TIMING_C)/\/\/\0/g' $(CONFIG_H_FILE)
	sed -i -E 's/^(#define MBEDTLS_HAVE_TIME_DATE)/\/\/\0/g' $(CONFIG_H_FILE)

# TODO connect to the platform's entropy source
ENTROPY_POLL_C_FILE := library/entropy_poll.c
patch-entropy-poll:
	sed -i -E 's/^(int mbedtls_platform_entropy_poll)/\0__dummy/g' $(ENTROPY_POLL_C_FILE)
	sed -i -E 's/^(#error "Platform entropy sources only work on).*/  int mbedtls_platform_entropy_poll\( void \*data, unsigned char \*output, size_t len, size_t \*olen \) \{ for \(int i = 0; i < len; i++\) \{ output[i] = 42; \}  \*olen = len;  return\( 0 \); \}/g' $(ENTROPY_POLL_C_FILE)

X509_CRT_C_FILE := library/x509_crt.c
patch-x509-crt:
	sed -i -E 's/^(#if defined\(MBEDTLS_FS_IO\))/#if 0/g' $(X509_CRT_C_FILE)

CIPHER_C_FILE := library/cipher.c
patch-cipher-info-from-string-xtensa:
	sed -i -E 's/^(const mbedtls_cipher_info_t \*mbedtls_cipher_info_from_string)/int strcmp_one\( const char \*s1, const char \*s2 \) \{ return 1; \}  \0/g' $(CIPHER_C_FILE)
	sed -i -E 's/strcmp\(/strcmp_one\(/g' $(CIPHER_C_FILE)

RSA_C_FILE := library/rsa.c
patch-rsa:
	sed -i -E 's/^(#if defined\(MBEDTLS_SELF_TEST\))/#if 0/g' $(RSA_C_FILE)

patch-fclose:
	sed -i -E 's/(fclose\( stream \))/0\/\*\0\*\//g' library/psa_its_file.c
	sed -i -E 's/(fclose\( f \))/\/\*\0\*\//g' library/ctr_drbg.c
	sed -i -E 's/(fclose\( f \))/\/\*\0\*\//g' library/hmac_drbg.c
	sed -i -E 's/(fclose\( f \))/\/\*\0\*\//g' library/entropy.c
	sed -i -E 's/(fclose\()/\/\/\0/g' library/entropy_poll.c
