rm -rf build
mkdir build
cd build

export OPENSSL_ROOT_DIR=/Users/yurykorolev/Projects/openssl-apple/libs/iPhoneOS/openssl.lib
# export LDFLAGS="-L/usr/local/opt/openssl@1.1/lib"
# export CPPFLAGS="-I/usr/local/opt/openssl@1.1/include"

# export OPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1


cmake \
  -DCMAKE_INSTALL_RPATH=@rpath/ \
  -DBUILD_SHARED_LIBS=OFF \
  -DWITH_EXAMPLES=OFF \
  -DCMAKE_BUILD_TYPE=Release \
  ..

make 

cd ..
