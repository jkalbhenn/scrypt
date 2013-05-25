mkdir -p temp
o=0
n=libscrypt
gcc -shared -O$o -std=c11 -fPIC src/scrypt.c -o temp/$n.so -lm -Wl,--version-script=build/$n.version && chmod 644 temp/$n.so
n=scrypt
gcc -O$o -std=c11 -lscrypt src/command-line-interface.c -o temp/scrypt && chmod 755 temp/scrypt
