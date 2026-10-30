#!/bin/sh
set -eu
mkdir -p bin
cc -std=c11 -D_DEFAULT_SOURCE -O2 -Wall -Wextra -Werror \
   -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie \
   -Wl,-z,relro,-z,now native/safe_filename.c -o bin/safe_filename
printf 'Secure native validator compiled.\n'
