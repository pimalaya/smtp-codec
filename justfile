export RUSTFLAGS := "-D warnings"
export RUSTDOCFLAGS := "-D warnings"

msrv := `sed -rn 's|^rust-version = \"(.*)\"$|\1|p' Cargo.toml`

[private]
default:
    just -l --unsorted

###########
### RUN ###
###########

# Run (local) CI
ci: (ci_impl ""           ""               ) \
    (ci_impl ""           " --all-features") \
    (ci_impl " --release" ""               ) \
    (ci_impl " --release" " --all-features")

[private]
ci_impl mode features: (check_impl mode features) (test_impl mode features)

# Check syntax, formatting, clippy, deny, semver, ...
check: (check_impl ""           ""               ) \
       (check_impl ""           " --all-features") \
       (check_impl " --release" ""               ) \
       (check_impl " --release" " --all-features")

[private]
check_impl mode features: (cargo_check mode features) \
                          (cargo_hack mode) \
                          cargo_fmt \
                          (cargo_clippy mode features) \
                          cargo_deny \
                          cargo_semver

[private]
cargo_check mode features:
    cargo check --workspace --all-targets{{ mode }}{{ features }}
    cargo doc --no-deps --document-private-items --keep-going{{ mode }}{{ features }}

[private]
cargo_hack mode: install_cargo_hack
    cargo hack check --workspace --all-targets{{ mode }}
    cargo hack check -p smtp-codec \
        --no-dev-deps \
        --exclude-features default \
        --feature-powerset \
        --group-features \
        arbitrary,\
        serde \
        --group-features \
        starttls,\
        ext_auth,\
        ext_size,\
        ext_8bitmime,\
        ext_pipelining,\
        ext_smtputf8,\
        ext_enhancedstatuscodes \
        --group-features \
        quirk_crlf_relaxed\
        {{ mode }}
    cargo hack check -p smtp-types \
        --no-dev-deps \
        --feature-powerset \
        --group-features \
        arbitrary,\
        serde \
        --group-features \
        starttls,\
        ext_auth,\
        ext_size,\
        ext_8bitmime,\
        ext_pipelining,\
        ext_smtputf8,\
        ext_enhancedstatuscodes\
        {{ mode }}

[private]
cargo_fmt: install_rust_nightly install_rust_nightly_fmt
    cargo +nightly fmt --check

[private]
cargo_clippy features mode: install_cargo_clippy
    cargo clippy --workspace --all-targets{{ features }}{{ mode }}

[private]
cargo_deny: install_cargo_deny
    cargo deny check

[private]
cargo_semver: install_cargo_semver_checks
    cargo semver-checks check-release --only-explicit-features -p smtp-codec
    cargo semver-checks check-release --only-explicit-features -p smtp-types

# Test multiple configurations
test: (test_impl ""           ""               ) \
      (test_impl ""           " --all-features") \
      (test_impl " --release" ""               ) \
      (test_impl " --release" " --all-features")

[private]
test_impl mode features: (cargo_test mode features)

[private]
cargo_test features mode:
    cargo test \
    --workspace \
    --all-targets \
    {{ features }}\
    {{ mode }}

# Audit advisories, bans, licenses, and sources
audit: cargo_deny

# Measure test coverage
coverage: install_rust_llvm_tools_preview install_cargo_grcov
    rm -rf target/coverage/*
    RUSTFLAGS="-Cinstrument-coverage" LLVM_PROFILE_FILE="$PWD/target/coverage/coverage-%m-%p.profraw" CARGO_TARGET_DIR="$PWD/target/coverage" cargo test -p smtp-codec -p smtp-types --all-features
    grcov target/coverage \
        --source-dir . \
        --binary-path target/coverage/debug \
        --branch \
        --keep-only '{smtp-codec/src/**,smtp-types/src/**}' \
        --llvm \
        --output-types "html,lcov" \
        --output-path target/coverage/
    mv target/coverage/lcov target/coverage/coverage.lcov
    rm target/coverage/*.profraw
    rm -rf target/coverage/debug

# Check MSRV
check_msrv: install_rust_msrv
    cargo '+{{ msrv }}' check --locked \
      --workspace \
      --all-targets --all-features
    cargo '+{{ msrv }}' test --locked \
      --workspace \
      --all-targets --all-features

# Check minimal dependency versions
check_minimal_dependency_versions: install_rust_nightly
    cargo +nightly update -Z minimal-versions
    cargo check \
      --workspace \
      --all-targets --all-features
    cargo test \
      --workspace \
      --all-targets --all-features
    cargo update

###############
### INSTALL ###
###############

# Install required tooling (ahead of time)
install: install_rust_msrv \
         install_rust_nightly \
         install_rust_nightly_fmt \
         install_rust_llvm_tools_preview \
         install_cargo_clippy \
         install_cargo_deny \
         install_cargo_grcov \
         install_cargo_hack \
         install_cargo_semver_checks

[private]
install_rust_msrv:
    rustup toolchain install '{{ msrv }}' --profile minimal

[private]
install_rust_nightly:
    rustup toolchain install nightly --profile minimal

[private]
install_rust_nightly_fmt:
    rustup component add --toolchain nightly rustfmt

[private]
install_rust_llvm_tools_preview:
    rustup component add llvm-tools-preview

[private]
install_cargo_clippy:
    rustup component add clippy

[private]
install_cargo_deny:
    cargo install --locked cargo-deny

[private]
install_cargo_grcov:
    cargo install grcov

[private]
install_cargo_hack:
    cargo install --locked cargo-hack

[private]
install_cargo_semver_checks:
    cargo install --locked cargo-semver-checks
