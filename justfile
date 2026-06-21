
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
install:
    cargo install --path .

# 安装 bash 补全到用户目录(无需 sudo;新开 shell 生效)。
# 其它 shell:`just completions zsh`(或 fish/elvish),输出自行 source / 安装。
completions SHELL="bash":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{SHELL}}" = "bash" ]; then
        d="$HOME/.local/share/bash-completion/completions"
        mkdir -p "$d"
        cargo run --quiet -- completions bash > "$d/zkv"
        echo "installed bash completion → $d/zkv (open a new shell)"
    else
        cargo run --quiet -- completions {{SHELL}}
    fi

