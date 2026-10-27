# Build and development tasks for shark.
# Run `just` to list recipes, `just <recipe>` to execute one.
#
# Notes
#   - the built binary lands in ./bin (see the `build` recipe)
#   - flags must come BEFORE the positional argument (Go flag semantics)
#   - with no positional argument, shark uses ./playlist.m3u8
#   - with no -o flag, the output is named <current_unix_time>.mp4 (or .ts
#     when ffmpeg is missing)

set shell := ["bash", "-euo", "pipefail", "-c"]

# Project metadata
mod := "shark"
bin := "./bin/shark"

version := `git describe --tags --always --dirty 2>/dev/null || echo dev`
ldflags := "-X main.version=" + version

# Default recipe: show the available recipes.
default:
    @just --list

# Build the binary into ./bin.
build:
    @mkdir -p ./bin
    go build -trimpath -ldflags "{{ldflags}}" -o "{{bin}}" .
    @echo "built {{bin}} ({{version}})"

# Build the Windows x64 binary into ./bin (cross-compiles, needs cgo nowhere).
windows:
    @mkdir -p ./bin
    GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "{{ldflags}}" -o "{{bin}}.exe" .
    @echo "built {{bin}}.exe ({{version}})"

# Build both platform binaries (run on Linux/macOS).
release: build windows
    @ls -lh {{bin}} {{bin}}.exe

# Cross-compile for the common platforms into ./bin/dist.
dist:
    @mkdir -p ./bin/dist
    for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
        os=$${target%/*}; arch=$${target#*/}; \
        out=./bin/dist/{{mod}}_$${os}_$${arch}; \
        [ "$$os" = "windows" ] && out=$$out.exe; \
        echo "building $$os/$$arch"; \
        GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "{{ldflags}}" -o "$$out" .; \
    done
    @echo "binaries in ./bin/dist"

# Build with the race detector.
race:
    @mkdir -p ./bin
    go build -race -o "{{bin}}-race" .

# Format all Go sources.
fmt:
    gofmt -w main.go

# Fail if anything is unformatted.
fmt-check:
    @gofmt -l . > fmtcheck.tmp
    @cat fmtcheck.tmp
    @test ! -s fmtcheck.tmp
    @rm -f fmtcheck.tmp
    @echo "formatting ok"

# Run go vet.
vet:
    go vet ./...

# Format check and vet: the pre-commit gate.
check: fmt-check vet

# Tidy the module files.
tidy:
    go mod tidy

# Build, then print the current version.
version:
    @just build
    @{{bin}} -version

# Build, then download ./playlist.m3u8; extra args are FLAGS placed before it:
#   just playlist -o "COMBINATIONAL CKT 09"
#   just playlist -proxy socks5://127.0.0.1:1080 -q
playlist *ARGS:
    @just build
    @{{bin}} {{ARGS}} playlist.m3u8

# Full control: you supply flags and the target yourself, in CLI order:
#   just run -o "COMBINATIONAL CKT 09" playlist.m3u8
#   just run -q 'https://vidcloud.eu.org/play.php?video_id=...'
#   just run -base https://bunny-cdn-qbg-s6.testwave.cc/ - < captured.m3u8
run *ARGS:
    @just build
    @{{bin}} {{ARGS}}

# Remove build output (plus the legacy binaries from the repo root).
clean:
    rm -rf ./bin
    rm -f shark shark.exe fmtcheck.tmp
