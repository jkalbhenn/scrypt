#the binary scrypt-kdf depends on libscrypt, so libscrypt is build and installed first, then scrypt-kdf

exit_on_error() {
  $* || exit 1
}

prefix=$1
mkdir -p temp

echo compile libscrypt
n=libscrypt
exit_on_error gcc -shared -O3 -std=c11 -fPIC -lm -o temp/$n.so source/scrypt.c
exit_on_error chmod 644 temp/$n.so

echo install libscrypt
exit_on_error install -m 644 -D temp/$n.so $prefix/usr/lib/$n.so
exit_on_error install -m 644 -D source/scrypt.h $prefix/usr/include/scrypt.h

echo compile scrypt-kdf
n=scrypt-kdf
exit_on_error gcc -O3 -std=c11 -lscrypt source/cli.c -o temp/$n
exit_on_error chmod 755 temp/$n

echo install scrypt-kdf
t=$prefix/usr/bin/$n
exit_on_error install -m 755 -D temp/$n $prefix/usr/bin/$n
