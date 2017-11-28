#!/bin/bash

cd vendor/
mv liboqs/ liboqs_old
wget https://github.com/christianpaquin/liboqs/archive/paquin_add-picnic_v2.zip
unzip paquin_add-picnic_v2
rm paquin_add-picnic_v2.zip
mv liboqs-paquin_add-picnic_v2/ liboqs
cd liboqs
cd src/sig_picnic
rm -rf external
wget https://github.com/IAIK/Picnic/archive/master.zip
unzip master
rm master.zip
mv Picnic-master/ external
./build_picnic.sh
cd ../..
autoreconf -i
./configure
make





