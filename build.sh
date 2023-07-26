#!/bin/bash

cmake -B build .

pushd build
make -j10
popd

