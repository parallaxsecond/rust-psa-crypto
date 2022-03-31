#!/usr/bin/python

import re

simple_define = re.compile(r'(.*)#define (MBEDTLS_[A-Z0-9_]+)$')
define_with_default = re.compile(r'.*#define (MBEDTLS_[A-Z0-9_]+) +([0-9A-Za-z_]+)')

def format(macro, state):
    return "    (\"%s\", %s)," % (macro, state.rjust(49 - len(macro) + len(state)))

for line in open('vendor/include/mbedtls/mbedtls_config.h').readlines():
    match = simple_define.match(line)

    if match:
        state = "Undefined" if match.group(1).strip() == '//' else "Defined"
        print(format(match.group(2), state))
    else:
        match = define_with_default.match(line)
        if match:
            print(format(match.group(1), "Undefined") + (" // default: %s" % (match.group(2))))

