---
layout: post
title:  "Path Constraints collected by Kirenenko"
date:   2021-03-07 22:00:00 -0800
categories: fuzzing
---

During the evaluation of [Kirenenko](https://github.com/ChengyuSong/Kirenenko),
we have collected a relatively large set of path constraints that might be useful
for tasks like test or benchmarking path constraint solvers like traditional SMT
solvers (e.g., [Z3](https://github.com/Z3Prover/z3),
[CVC4](https://cvc4.github.io/), [Yices](https://yices.csl.sri.com/)) and
fuzzing-based solvers (e.g., [JFS](https://github.com/mc-imperial/jfs),
[fuzzolic](https://season-lab.github.io/fuzzolic/)).
The main difference from other path constraint dataset is that we've also
recorded concrete values of inputs bytes, which can be useful for solving nested
branch constraints as the current input already satisfies the all previous path
constraints so searching from current input could be easier to find a new input
that can flip the last branch.

The constraints are collected from 14 programs. We first used AFL to fuzz them
for over 24 hours, then use Kirenenko to collect the path constraints. We
applied a lightweight filter (calling context + branch address) to reduce the
number of potential duplicated constraints. Collected constraints are then
serialized using protobuf. Constraints from nested branches are also included
(as pointers to previous records).

The list of programs are:

* dtls
* file
* libjpeg
* libxml2
* nm (binutils)
* objdump (binutils)
* openssl
* readelf (binutils)
* readpng (libpng)
* size (binutils)
* sqlite3
* tcpdump (libpcap)
* tiff2pdf (libtiff)
* vorbis

You can download the archives [here](https://www.dropbox.com/sh/aebml54m4g5erjm/AABO_tIpjfSui_fRWlnG-X1Ga?dl=0).
My student has also prepared an example on how to load the constraints and feed
to Z3, which can be find [here](https://github.com/chenju2k6/z3-test).

Have fun!
