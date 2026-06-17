
dev:
    RUST_LOG=debug cargo run

build:
    cargo build

# PTY 端到端测试:驱动真实 zkv 二进制(80x24 pty)。
e2e:
    cargo build
    python3 tests/e2e_pty.py -v

# 截图:驱动 zkv 各界面,在 Xvfb 里用真 xterm 渲染后截图存入 screenshot/。
# 依赖:Xvfb / xterm / xdotool / ImageMagick(import)。Fedora:
#   sudo dnf install xorg-x11-server-Xvfb xterm xdotool ImageMagick
shots:
    cargo build
    python3 tests/screenshot.py

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