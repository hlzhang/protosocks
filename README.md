

```shell script
cargo test --no-default-features --features=proto-ipv4
cargo test --no-default-features --features=proto-ipv6
cargo test --no-default-features --features=proto-ipv4,proto-ipv6
cargo test --no-default-features --features=proto-ipv4,proto-ipv6,std

cargo clippy --all --all-targets
cargo fmt --all -- --check
```

cargo-tarpaulin
```shell script
docker run --rm -it -v "${PWD}:/volume" --workdir "/volume" -e RUST_BACKTRACE=full -e RUST_LOG=debug rust:latest cargo test --lib -- --exact --nocapture --test-threads=1
docker run --rm -it --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin sh -c "cargo tarpaulin --out Html"
#docker run --rm -it --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin sh -c "cargo tarpaulin --run-types Doctests --all"
#docker run --rm -it --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin sh -c "cargo tarpaulin --run-types Tests --all"
#docker run --rm -it --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin sh -c "cargo tarpaulin --run-types Doctests Tests --all"
```
