
dev:
    RUST_LOG=debug cargo run

build:
    cargo build

release:
    cargo build --release


release-patch:
    cargo release patch --no-publish --execute

release-minor:
    cargo release minor --no-publish --execute

release-major:
    cargo release major --no-publish --execute

upgrade:
    cargo +nightly update --breaking -Z unstable-options

publish-dry:
    cargo publish --dry-run --registry crates-io

publish:
    cargo publish --registry crates-io