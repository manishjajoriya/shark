# shark

`vidcloud.eu.org` (play.php) lecture / HLS downloader - a single-file,
cross-platform (Windows/Linux) program built **only from the Go standard
library**.

It:

1. fetches the `play.php` page,
2. parses the AES-encrypted hidden inputs (`enc_video_url`, `enc_drm_type`, ...),
3. decrypts them (AES-128-CBC + PKCS7) into the signed `.docx` HLS URL,
4. downloads the HLS manifest (master + best variant + separate audio when needed),
5. downloads every segment (concurrency, retries, AES-128 `EXT-X-KEY` support),
6. merges natively (TS/fMP4 concat). If `ffmpeg` is installed it remuxes to a
   clean MP4; otherwise the raw merged stream is kept as-is.

Instead of a URL you can pass a local playlist file (or `-` for stdin), e.g. a
media playlist captured from the player's network tab. Relative segment URIs
are resolved against `-base`.

```
Progress: [####----------------] 20% (200/1000, 12.3 MB)
```

## Build

```sh
just build          # -> ./bin/shark, version stamped from git
just windows        # -> ./bin/shark.exe (cross-compiles from Linux/macOS)
just dist           # -> ./bin/dist/shark_{linux,darwin,windows}_{amd64,arm64}
just --list         # all recipes
```

`just build` injects the version into the binary via `-ldflags "-X
main.version=..."`, where the version comes straight from git: the newest tag,
`<tag>-<n>-g<hash>` after it, the short commit hash before any tag, plus
`-dirty` for a modified working tree. A plain `just`-less build falls back to
`dev`:

```sh
go build .          # ./shark --version -> "shark dev"
./bin/shark -version   # -> e.g. "shark 1.2-3-g1a2b3c4"
```

Tag the repo (`git tag 1.1`) to make releases report a clean version.

## Usage

```sh
./bin/shark 'https://vidcloud.eu.org/play.php?video_id=...' -o "LECTURE 09"
./bin/shark playlist.m3u8                            # local captured playlist
./bin/shark - < captured.m3u8                        # playlist from stdin
./bin/shark -base https://bunny-cdn-qbg-s6.testwave.cc/ playlist.m3u8
```

- With no argument, shark uses `./playlist.m3u8`.
- With no `-o`, the output is named `<unix_time>.mp4` (`.ts` when ffmpeg is
  missing).
- Any non-`play.php` URL is treated as a direct playlist URL (master or media).
- When the content CDN answers `403`, the signed URL is region/IP-bound: use
  `-proxy` (or a system proxy via the environment) with a residential IP /
  VPN in the streaming region.

### Flags

| flag | default | meaning |
|------|---------|---------|
| `-o` | | output base name (extension added automatically) |
| `-level` | `-1` | variant index in the master playlist (`-1` = highest) |
| `-conc` | `6` | parallel segment downloads (capped at 16) |
| `-no-remux` | `false` | skip ffmpeg even when available |
| `-keep` | `false` | keep the intermediate file after a successful remux |
| `-base` | content CDN | base URL used to resolve relative segment URIs from a local playlist file |
| `-proxy` | | proxy for all requests, e.g. `http://127.0.0.1:7890` or `socks5://127.0.0.1:1080` |
| `-q` | `false` | quiet: suppress status/progress output |
| `-version` | | print the version |
| `-h` | | usage |

## Progress indicator

While segments download, shark draws the progress **in place on a single
terminal line** - each update returns the cursor to the start of the line with
a carriage return and overwrites the previous frame (pad-clearing when the new
frame is shorter), so the line never scrolls:

```
Progress: [####----------------] 20% (200/1000, 12.3 MB)
Progress: [########------------] 40% (400/1000, 24.6 MB)
Progress: [############--------] 60% (600/1000, 36.9 MB)
...
Progress: [####################] 100% (1000/1000, 61.5 MB)
merged 1000 segments, 61.5 MB
```

- stdout is flushed after every write (Go's `os.Stdout` is unbuffered), so
  frames appear immediately and update smoothly.
- No newline is printed while running; the line is released exactly once -
  when the run completes (final `100%` frame, then the summary) or is
  abandoned on error / `Ctrl+C`, so the next output always starts clean.
- When stdout is **not** a terminal (pipe, file), `\r` tricks are useless, so
  the indicator falls back to plain, newline-terminated lines drawn for at
  most every 10th update.
- `-q` disables progress output entirely.

## Installing

Put a binary from `just dist` on your `PATH` (or `go install .` for a `dev`
version):

```sh
sudo install -m 755 bin/shark /usr/local/bin/
```
