#!/bin/bash
../newlib-1.18.0/configure --target=mips-cnu-elf --prefix=/usr/local
make
sudo make install
