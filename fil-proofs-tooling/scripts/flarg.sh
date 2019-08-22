#!/usr/bin/env bash

post_sector_counts=(2 4 8)

RUST_BACKTRACE=1 RUST_LOG=info env time -f "max mem: '%MKB'" cargo run --color=always --package fil-proofs-tooling --bin blarg --release -- 16 0

for t in ${post_sector_counts[@]}; do
  sed -i -E "s/^pub const POST_SECTORS_COUNT.*$/pub const POST_SECTORS_COUNT: usize = $t;/" filecoin-proofs/src/constants.rs
  echo "sealing and generating PoSts with POST_SECTORS_COUNT=$t"
  RUST_BACKTRACE=1 RUST_LOG=info env time -f "max mem: '%MKB'" cargo run --color=always --package fil-proofs-tooling --bin blarg --release -- 8 1
done
