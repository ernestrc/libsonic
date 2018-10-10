# Libsonic [![Build Status](https://travis-ci.org/ernestrc/libsonic.svg)](https://travis-ci.org/ernestrc/libsonic)

## Build instructions
Run configure script and then make:
```sh
$ ./configure
$ make
$ make install
```
If you have problems linking with a system dependency, you can configure the project to build the dependency from source:
```sh
$ ./configure --enable-build-libuv --enable-build-h2o
$ make
```
Alternatively, you can provide your own CFLAGS or LDFLAGS:
```sh
$ ./configure CFLAGS='-DWITH_BUNDLED_SSL=off'
$ make
```
For a full list of options run `./configure --help`.

Please refer to the Docker images in [utils](utils) to see some of the common options and CFLAGS used by the different Linux distros.

## MacOS Build instructions
Assuming you have Homebrew installed:
```
$ brew update && brew bundle --file=utils/Brewfile
$ export LIBTOOL=glibtool
$ export LIBTOOLIZE=glibtoolize
$ ./configure --enable-build-all
$ make && make install
```

Please refer to MacOS section in [.travis.yml](.travis.yml) to see the latest build options.

## Running tests
Configure and enable the development build:
```sh
$ ./configure --enable-develop
$ make
$ make test
```
