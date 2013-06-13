#scrypt depends on an installed libscrypt

prefix=$1
mkdir -p temp
o=0

#compile libscrypt
n=libscrypt
gcc -shared -O$o -std=c11 -fPIC src/scrypt.c -o temp/$n.so -lm -Wl,--version-script=build/export && chmod 644 temp/$n.so

#install libscrypt
install -m 644 -D temp/$n.so $prefix/usr/lib/$n.so
install -m 644 -D src/scrypt.h $prefix/usr/include/scrypt.h

#compile scrypt-kdf
n=scrypt-kdf
gcc -O$o -std=c11 -lscrypt src/cli.c -o temp/$n && chmod 755 temp/$n

#install scrypt-kdf
t=$prefix/usr/bin/$n
install -m 755 -D temp/$n $prefix/usr/bin/$n
