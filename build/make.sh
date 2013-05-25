mkdir -p temp
o=3
n=libscrypt
gcc -shared -O$o -std=c11 -fPIC src/scrypt.c -o temp/$n.so -lm -Wl,--version-script=build/$n.version && chmod 644 temp/$n.so
n=scrypt
gcc -O$o -std=c11 -lscrypt src/cli.c -o temp/scrypt && chmod 755 temp/scrypt
