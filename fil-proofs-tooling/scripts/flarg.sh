#!/usr/bin/env bash

post_sector_counts=(2 4 8 16 32)
#
#for t in ${post_sector_counts[@]}; do
#  sed -i -E "s/^pub const POST_SECTORS_COUNT.*$/pub const POST_SECTORS_COUNT: usize = $t;/" filecoin-proofs/src/constants.rs
#  cat filecoin-proofs/src/constants.rs | grep POST_SECTORS_COUNT
#  echo "generating parameters for POST_SECTORS_COUNT=$t"
#  RUST_BACKTRACE=1 RUST_LOG=info cargo run --color=always --package filecoin-proofs --bin paramcache --release
#done
#
#RUST_BACKTRACE=1 RUST_LOG=info env time -f "max mem: '%MKB'" cargo run --color=always --package fil-proofs-tooling --bin blarg --release -- 32 1

for t in ${post_sector_counts[@]}; do
  sed -i -E "s/^pub const POST_SECTORS_COUNT.*$/pub const POST_SECTORS_COUNT: usize = $t;/" filecoin-proofs/src/constants.rs
  echo "generating PoSts for 64 sectors with POST_SECTORS_COUNT=$t"
  RUST_BACKTRACE=1 RUST_LOG=info RUST_BACKTRACE=1 RUST_LOG=info env time -f "max mem: '%MKB'" cargo run --color=always --package fil-proofs-tooling --bin blarg --release -- 32 0
done
