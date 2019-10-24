#!/bin/bash

# Reset if no debug system desired
DEBUG="-d"

if [ "$#" -lt 1 ]; then
   echo "Usage: $0 [desired-oqssl-installpath]. Exiting."
   echo "   Note: Use of substrings 'stat' or 'dyn' drive build to static or dynamic linkage mode respectively."
   echo "   Default: stat[ic]"
   exit -1
fi

if [[ $1 == *"dyn"* ]]; then
   DYN="1"
   echo "Building dynamic libs"
else
   echo "Building static libs"
fi

# In case a non-standard location is provided...
mkdir -p $1

cd /root/sh

# Just in case some environment-specific defines would be needed....
HOST=`uname -n`
if test -f "../Makefile.$HOST"; then
   source ../Makefile.$HOST
else
   cd ..; BUILDDIR=`pwd`/build
fi
if [ -d "$BUILDDIR" ]; then
    echo "$BUILDDIR exists"
else
    mkdir "$BUILDDIR"
fi

cd $BUILDDIR

# Cleanup just in case:
if [ -d openssl ]; then
   cd openssl; make uninstall
   cd ..
   rm -rf liboqs openssl
fi

# Get Code:
echo "Building stable OpenSSL 1.1.1"

# Get main OQS openssl:
git clone --branch OQS-OpenSSL_1_1_1-stable https://github.com/open-quantum-safe/openssl.git
# Activate this for CMS support:
# git clone git@github.com:zrlmib/openssl.git

# liboqs:
git clone --branch master https://github.com/open-quantum-safe/liboqs.git

# Build liboqs
cd liboqs
autoreconf -i
if [ "$DYN" == "" ]; then
   ./configure --prefix=$BUILDDIR/openssl/oqs --enable-shared=no 
else
   ./configure --prefix=$BUILDDIR/openssl/oqs --enable-shared=yes 
fi
make -j 1

if [ "$?" -ne 0 ]; then
   echo "Error building liboqs. Exiting."
   exit -1
fi

make install
if [ "$?" -ne 0 ]; then
   echo "Error installing liboqs. Exiting."
   exit -1
fi

# Build Openssl
cd ../openssl
if [ "$DYN" == "" ]; then
  ./config $DEBUG --prefix=$1 --openssldir=$1 no-shared
else
  ./config $DEBUG --prefix=$1 --openssldir=$1 -Wl,-rpath=$1/lib
fi

# Modify version string:
mv include/openssl/opensslv.h include/openssl/opensslv.h-orig
sed -e 's/OpenSSL 1.1.1d  10 Sep 2019/OpenSSL 1.1.1d  10 Sep 2019 with OQS support/g' include/openssl/opensslv.h-orig > include/openssl/opensslv.h

make -j 1
if [ "$?" -ne 0 ]; then
   echo "Error building openssl. Exiting."
   exit -1
fi


read -p 'Do full test? (y/n): Takes about 30 mins' fulltest
if [[ "$fulltest" == "y" ]]; then
   cd oqs_test
   # don't do full build again:
   grep -v scripts run.sh > clean-run.sh 
   chmod u+x clean-run.sh
   ./clean-run.sh
   cd ..
fi


if [ "$?" -eq 0 ]; then
  make install
  # also install the oqs includes and libs:
  if [ "$DYN" == "" ]; then
    cd oqs/include; cp -R oqs $1/include/
    cd ../lib; cp *.a $1/lib
  else
    cd oqs/include; cp -R oqs $1/include/
    cd ../lib; cp *.so* $1/lib
  fi
  export PATH=$1/bin:$PATH
  echo "export PATH=$1/bin:$PATH" >> /root/.bashrc
else
   "echo openssl didn't seem to build OK. Not installing"
   exit 1
fi

# Smoketest Openssl
openssl version
openssl list -public-key-algorithms

