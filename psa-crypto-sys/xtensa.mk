all: psa-xtensa

psa-xtensa: patch-config-xtensa patch-x509-crt patch-cipher-info-from-string-xtensa
	make -j CC=$(XTENSA_GCC) CFLAGS="-O2 -DMBEDTLS_NO_PLATFORM_ENTROPY=1 -DMBEDTLS_USE_PSA_CRYPTO=1" lib

CONFIG_H_FILE := include/mbedtls/mbedtls_config.h
patch-config-xtensa:
	sed -i -E 's/^(#define MBEDTLS_NET_C)/\/\/\0/g' $(CONFIG_H_FILE)
	sed -i -E 's/^(#define MBEDTLS_TIMING_C)/\/\/\0/g' $(CONFIG_H_FILE)
	sed -i -E 's/^(#define MBEDTLS_HAVE_TIME_DATE)/\/\/\0/g' $(CONFIG_H_FILE)

X509_CRT_C_FILE := library/x509_crt.c
patch-x509-crt:
	sed -i -E 's/^(#if defined\(MBEDTLS_FS_IO\))/#if 0/g' $(X509_CRT_C_FILE)

CIPHER_C_FILE := library/cipher.c
patch-cipher-info-from-string-xtensa:
	sed -i -E 's/^(const mbedtls_cipher_info_t \*mbedtls_cipher_info_from_string)/int strcmp_one\( const char \*s1, const char \*s2 \) \{ return 1; \}  \0/g' $(CIPHER_C_FILE)
	sed -i -E 's/strcmp\(/strcmp_one\(/g' $(CIPHER_C_FILE)