# protosocks

Socks5 protocol lib in Rust  

Its design goals are simplicity and robustness. Its design anti-goals include complicated compile-time computations, such as macro or type tricks, even at cost of performance degradation.  

Features
+ RFC1928
+ RFC1929
+ IPv4
+ IPv6


Test by using rust-lang Docker image
`docker run --rm -it -v "${PWD}:/volume" --workdir "/volume" -e RUST_BACKTRACE=full -e RUST_LOG=debug rust:latest cargo test --lib -- --exact --nocapture --test-threads=1`

Test different combinations of features
```shell script
cargo test --no-default-features --features=proto-ipv4
cargo test --no-default-features --features=proto-ipv6
cargo test --no-default-features --features=proto-ipv4,proto-ipv6
cargo test --no-default-features --features=proto-ipv4,proto-ipv6,std

cargo clippy --all --all-targets
cargo fmt --all -- --check
```

Generate test coverage report (cargo-tarpaulin)
```shell script
docker run --rm -it --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin sh -c "cargo tarpaulin --out Html"
#docker run --rm -it --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin sh -c "cargo tarpaulin --run-types Doctests --all"
#docker run --rm -it --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin sh -c "cargo tarpaulin --run-types Tests --all"
#docker run --rm -it --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin sh -c "cargo tarpaulin --run-types Doctests Tests --all"
```
