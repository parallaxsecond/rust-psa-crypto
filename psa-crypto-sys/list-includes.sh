#!/bin/sh

cd vendor/include/mbedtls
ls -f1 $(
 (
      grep '^#include' * |grep -v '<'|grep -v MBEDTLS_|sed 's/:#include//;s/"//g'|sed 's#mbedtls/##g'| egrep -v ' (psa/crypto.h|psa/crypto_config.h|everest/everest.h|zlib.h|.*_alt.h)$';
      ls *.h|awk '{print $1 " " $1}'
 )|tsort|tac|
 egrep -v '^(compat-1.3.h|certs.h|config.h|check_config.h)$'
)
