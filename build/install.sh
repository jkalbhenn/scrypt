prefix=$1
t=$prefix/usr/lib/libscrypt.so
cp temp/libscrypt.so $t && chmod 644 $t
t=$prefix/usr/include/scrypt.h
cp src/scrypt.h $t && chmod 644 $t
t=$prefix/usr/bin/scrypt
cp temp/scrypt $t && chmod 755 $t
