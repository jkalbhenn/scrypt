#scrypt depends on an installed libscrypt

mkdir -p temp
o=3

#compile libscrypt
n=libscrypt
gcc -shared -O$o -std=c11 -fPIC src/scrypt.c -o temp/$n.so -lm -Wl,--version-script=build/export && chmod 644 temp/$n.so

#install libscrypt
prefix=$1
t=$prefix/usr/lib/$n.so
cp temp/$n.so $t && chmod 644 $t
t=$prefix/usr/include/scrypt.h
cp src/scrypt.h $t && chmod 644 $t

#compile scrypt-kdf
n=scrypt-kdf
gcc -O$o -std=c11 -lscrypt src/cli.c -o temp/$n && chmod 755 temp/$n

#install scrypt-kdf
t=$prefix/usr/bin/$n
cp temp/$n $t && chmod 755 $t
