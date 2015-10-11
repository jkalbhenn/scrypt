#the binary scrypt-kdf depends on libscrypt, so libscrypt is build and installed first, then scrypt-kdf

prefix=$1
mkdir -p temp

echo compile libscrypt
n=libscrypt
gcc -shared -O3 -std=c11 -fPIC source/scrypt.c -o temp/$n.so -lm -Wl,--version-script=other/export && chmod 644 temp/$n.so

echo install libscrypt
install -m 644 -D temp/$n.so $prefix/usr/lib/$n.so
install -m 644 -D source/scrypt.h $prefix/usr/include/scrypt.h

echo compile scrypt-kdf
n=scrypt-kdf
gcc -O3 -std=c11 -lscrypt source/cli.c -o temp/$n && chmod 755 temp/$n

echo install scrypt-kdf
t=$prefix/usr/bin/$n
install -m 755 -D temp/$n $prefix/usr/bin/$n
