// shark - vidcloud.eu.org (play.php) lecture downloader.
//
// Single-file, cross-platform (Windows/Linux) program built only from the Go
// standard library. It:
//  1. fetches the play.php page,
//  2. parses the AES-encrypted hidden inputs (enc_video_url, enc_drm_type, ...),
//  3. decrypts them (AES-128-CBC, PKCS7) into the signed .docx HLS URL,
//  4. downloads the HLS manifest (master + best variant + separate audio when needed),
//  5. downloads every segment (concurrency, retries, AES-128 EXT-X-KEY support),
//  6. merges natively (TS/fMP4 concat). If ffmpeg is installed it remuxes to
//     a clean MP4; otherwise the raw merged stream is kept as-is.
//
// Instead of a URL you can pass a local playlist file (or "-" for stdin), e.g. a
// media playlist captured from the player's network tab. Relative segment URIs
// are resolved against the -base host (default: the known content CDN).
//
// Build:  just build  ->  ./bin/shark (version stamped from git via -ldflags)
//
//	or: go build .
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

// ---------------------------------------------------------------------------
// Constants recovered from the site's obfuscated player (video-script.js):
// AES-128-CBC + PKCS7 with
//
//	key = Utf8("R7@kP4#xL9!mQ2$v")  = atob("UjdAa1A0I3hMOSFtUTIkdg==")
//	iv  = Utf8("T3!nW8$qZ5@rK1#p") = atob("VDMhblc4JHFaNUBySzEjcA==")
//
// ---------------------------------------------------------------------------
const (
	encKeyStr = "R7@kP4#xL9!mQ2$v"
	encIVStr  = "T3!nW8$qZ5@rK1#p"
)

// Headers copied from a working browser capture (DevTools "Copy as cURL"
// of a segment request). The content CDN is fussy about them.
const browserUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
const siteOrigin = "https://vidcloud.eu.org"
const siteReferer = "https://vidcloud.eu.org/"
const secChUa = `"Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156"`

// version is stamped at build time from git (see the justfile):
//
//	go build -trimpath -ldflags "-X main.version=$(git describe --tags --always --dirty)"
//
// which yields the tag, or "<tag>-<n>-g<hash>" after it, the bare short commit
// hash before any tag, and "-dirty" appended for a working tree with changes.
// A plain `go build` without the flag leaves the "dev" fallback in place.
var version = "dev"

// ---------------------------------------------------------------------------
// tiny helpers
// ---------------------------------------------------------------------------

func pf(format string, a ...any) { fmt.Printf(format+"\n", a...) }

func fatal(err error) { log.Fatalf("shark: %v", err) }

func logf(q bool, format string, a ...any) {
	if !q {
		pf(format, a...)
	}
}

// unpadPKCS7 strips padding per PKCS#7.
func unpadPKCS7(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("empty plaintext after decrypt")
	}
	p := int(b[len(b)-1])
	if p == 0 || p > aes.BlockSize || p > len(b) {
		return nil, fmt.Errorf("invalid PKCS7 padding byte %d", p)
	}
	for _, c := range b[len(b)-p:] {
		if int(c) != p {
			return nil, errors.New("corrupted PKCS7 padding")
		}
	}
	return b[:len(b)-p], nil
}

// aes128DecryptCBC decrypts and unpads in one shot.
func aes128DecryptCBC(ct, key, iv []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("key must be 16 bytes, got %d", len(key))
	}
	if len(iv) != 16 {
		return nil, fmt.Errorf("iv must be 16 bytes, got %d", len(iv))
	}
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length %d not a multiple of 16", len(ct))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	return unpadPKCS7(out)
}

func decodeBase64Any(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, " ", "")
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

var htmlUnescaper = strings.NewReplacer(
	"&amp;", "&", "&quot;", `"`, "&#39;", "'", "&apos;", "'",
	"&lt;", "<", "&gt;", ">", "&nbsp;", " ",
)

// grabHidden extracts value= of an <input> by id or name (both attr layouts).
func grabHidden(html, id string) string {
	xid := `(?:id|name)\s*=\s*"` + regexp.QuoteMeta(id) + `"`
	pats := []string{
		`(?is)<input[^>]*` + xid + `[^>]*value\s*=\s*"([^"]*)"`,
		`(?is)<input[^>]*value\s*=\s*"([^"]*)"[^>]*` + xid,
	}
	for _, p := range pats {
		if m := regexp.MustCompile(p).FindStringSubmatch(html); m != nil {
			return htmlUnescaper.Replace(m[1])
		}
	}
	return ""
}

// sanitize makes a Windows- and Linux-safe filename.
func sanitize(name string) string {
	const bad = "<>:\"/\\|?*\x7f"
	var b strings.Builder
	for _, r := range name {
		switch {
		case unicode.IsControl(r):
			b.WriteRune(' ')
		case strings.ContainsRune(bad, r) || r < 0x20:
			b.WriteRune('_')
		default:
			b.WriteRune(r)
		}
	}
	s := strings.Join(strings.Fields(b.String()), " ")
	s = strings.TrimSpace(strings.Trim(s, ". "))
	r := []rune(s)
	if len(r) > 150 {
		s = string(r[:150])
	}
	if s == "" {
		s = "video"
	}
	up := strings.ToUpper(s)
	for _, reserved := range []string{"CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"} {
		if up == reserved || strings.HasPrefix(up, reserved+".") {
			s = "_" + s
			break
		}
	}
	return s
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

type client struct {
	hc *http.Client
}

func newClient(proxyURL string) *client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		fatal(err)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConns = 16
	tr.MaxIdleConnsPerHost = 16
	if proxyURL != "" {
		pu, err := url.Parse(proxyURL)
		if err != nil || pu.Host == "" {
			fatal(fmt.Errorf("invalid proxy URL %q (use http://host:port or socks5://host:port)", proxyURL))
		}
		tr.Proxy = http.ProxyURL(pu)
	} else {
		tr.Proxy = http.ProxyFromEnvironment
	}
	return &client{
		hc: &http.Client{
			Transport: tr,
			Jar:       jar,
			Timeout:   120 * time.Second,
		},
	}
}

// get fetches a URL with the browser's cross-site CORS headers (segments,
// manifests, keys - the shape captured from the player) and retries.
func (c *client) get(rawURL string, accept string, retries int) ([]byte, error) {
	return c.fetch(rawURL, accept, retries, false)
}

// getPage fetches an HTML page the way a top-level navigation would (play.php).
func (c *client) getPage(rawURL string, retries int) ([]byte, error) {
	return c.fetch(rawURL, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", retries, true)
}

func (c *client) fetch(rawURL, accept string, retries int, nav bool) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(600*attempt) * time.Millisecond)
		}
		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", browserUA)
		req.Header.Set("Accept", accept)
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Sec-Ch-Ua", secChUa)
		req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
		req.Header.Set("Sec-Ch-Ua-Platform", `"Linux"`)
		if nav {
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Sec-Fetch-User", "?1")
			req.Header.Set("Upgrade-Insecure-Requests", "1")
		} else {
			req.Header.Set("Origin", siteOrigin)
			req.Header.Set("Referer", siteReferer)
			req.Header.Set("Cache-Control", "no-cache")
			req.Header.Set("Pragma", "no-cache")
			req.Header.Set("Sec-Fetch-Dest", "empty")
			req.Header.Set("Sec-Fetch-Mode", "cors")
			req.Header.Set("Sec-Fetch-Site", "cross-site")
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20)) // 256 MiB cap
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d for %s", resp.StatusCode, rawURL)
			if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
				continue
			}
			return body, lastErr
		}
		return body, nil
	}
	return nil, lastErr
}

// ---------------------------------------------------------------------------
// play.php page -> decrypted stream URL
// ---------------------------------------------------------------------------

type encFields struct {
	videoURL   string
	drmType    string
	keyID      string
	keyValue   string
	licenseURL string
	statusURL  string
}

func decryptEncFields(html string, key, iv []byte) (*encFields, error) {
	b64url := grabHidden(html, "enc_video_url")
	if b64url == "" {
		if strings.Contains(html, `id="enc_video_url"`) {
			return nil, errors.New(
				"play.php rendered the player but enc_video_url is empty - the site is " +
					"redacting/gating video data for this IP (or the video is unavailable). " +
					"Retry from a residential IP / VPN via -proxy, or pass a captured " +
					"playlist .m3u8 file instead")
		}
		return nil, errors.New("enc_video_url not found on the page")
	}
	dec := func(b64 string) ([]byte, error) {
		ct, err := decodeBase64Any(b64)
		if err != nil {
			return nil, err
		}
		return aes128DecryptCBC(ct, key, iv)
	}
	plain, err := dec(b64url)
	if err != nil {
		return nil, fmt.Errorf("decrypt enc_video_url: %w", err)
	}
	out := &encFields{videoURL: strings.TrimSpace(string(plain))}
	if !strings.HasPrefix(out.videoURL, "http") {
		return nil, fmt.Errorf("decrypted value does not look like a URL: %q", truncate(out.videoURL, 120))
	}
	for _, f := range []struct {
		id  string
		dst *string
	}{
		{`enc_drm_type`, &out.drmType},
		{`enc_key_id`, &out.keyID},
		{`enc_key_value`, &out.keyValue},
		{`enc_license_url`, &out.licenseURL},
		{`enc_status_url`, &out.statusURL},
	} {
		src := grabHidden(html, f.id)
		if src == "" {
			continue
		}
		if b, derr := dec(src); derr == nil {
			*f.dst = strings.TrimSpace(string(b))
		}
	}
	return out, nil
}

func extractTitle(pageURL *url.URL, pageHTML string) string {
	if pageURL != nil {
		if v := pageURL.Query().Get("video_name"); v != "" {
			return sanitize(v)
		}
	}
	m := regexp.MustCompile(`(?is)<[a-z]+[^>]*?id="player-title"[^>]*>(.*?)<`).FindStringSubmatch(pageHTML)
	if m != nil {
		t := htmlUnescaper.Replace(m[1])
		t = strings.TrimSpace(strings.Join(strings.Fields(t), " "))
		if t != "" {
			return sanitize(t)
		}
	}
	return sanitize("video")
}

// ---------------------------------------------------------------------------
// HLS data model
// ---------------------------------------------------------------------------

type hlsKey struct {
	method string // NONE | AES-128 | SAMPLE-AES
	uri    string
	iv     []byte // explicit IV (nil => derive from media sequence)
}

type byteRange struct {
	length int64
	offset int64 // -1 => determined sequentially
}

type hlsSegment struct {
	uri      string
	dur      float64
	key      hlsKey
	initURI  string
	byRange  *byteRange
	mediaSeq uint64
}

type mediaHints struct {
	targetDur int
	isFmp4    bool
	audioOnly bool
}

type variantEntry struct {
	uri     string
	bw      int64
	res     string
	codecs  string
	audio   string
	isAudio bool
}

type audioEntry struct {
	name string
	uri  string
}

type streamDesc struct {
	segments []hlsSegment
	hints    mediaHints
	audioURI string
}

// ---------------------------------------------------------------------------
// playlist parsing
// ---------------------------------------------------------------------------

func splitAttrLine(s string) map[string]string {
	out := map[string]string{}
	var cur strings.Builder
	inQ := false
	var fields []string
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '"':
			inQ = !inQ
			cur.WriteByte(ch)
		case ch == ',' && !inQ:
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		fields = append(fields, cur.String())
	}
	for _, f := range fields {
		if i := strings.IndexByte(f, '='); i >= 0 {
			k := strings.ToUpper(strings.TrimSpace(f[:i]))
			v := strings.Trim(strings.TrimSpace(f[i+1:]), `"`)
			out[k] = v
		}
	}
	return out
}

func isVideoCodecs(codecs string) bool {
	low := strings.ToLower(codecs)
	for _, v := range []string{"avc", "h264", "hvc", "hevc", "hev1", "av01", "vp9", "vp8", "av1", "mp4v"} {
		if strings.Contains(low, v) {
			return true
		}
	}
	return low == "" // absent codecs -> assume video
}

func parseMasterMedia(text string, base *url.URL) map[string]audioEntry {
	out := map[string]audioEntry{}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if !strings.HasPrefix(line, "#EXT-X-MEDIA:") {
			continue
		}
		a := splitAttrLine(line[len("#EXT-X-MEDIA:"):])
		if strings.ToUpper(a["TYPE"]) != "AUDIO" || a["URI"] == "" || a["GROUP-ID"] == "" {
			continue
		}
		u, err := base.Parse(a["URI"])
		if err != nil {
			continue
		}
		if _, ok := out[a["GROUP-ID"]]; !ok {
			out[a["GROUP-ID"]] = audioEntry{name: a["NAME"], uri: u.String()}
		}
	}
	return out
}

func parseMaster(text string, base *url.URL) []variantEntry {
	var variants []variantEntry
	var pend *variantEntry
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		switch {
		case strings.HasPrefix(line, "#EXT-X-STREAM-INF:"):
			a := splitAttrLine(line[len("#EXT-X-STREAM-INF:"):])
			bw, _ := strconv.ParseInt(a["BANDWIDTH"], 10, 64)
			pend = &variantEntry{bw: bw, res: a["RESOLUTION"], codecs: a["CODECS"], audio: a["AUDIO"]}
		case line != "" && !strings.HasPrefix(line, "#"):
			if pend == nil {
				continue
			}
			if u, err := base.Parse(line); err == nil {
				pend.uri = u.String()
				pend.isAudio = pend.codecs != "" && !isVideoCodecs(pend.codecs)
				variants = append(variants, *pend)
			}
			pend = nil
		}
	}
	return variants
}

func resolveStream(c *client, streamURL string, wantLevel int, q bool) (*streamDesc, error) {
	body, err := c.get(streamURL, "application/vnd.apple.mpegurl,*/*", 3)
	if err != nil {
		return nil, err
	}
	text := string(body)
	base := mustParse(streamURL)
	trimmed := strings.TrimSpace(text)
	if strings.Contains(trimmed, "AccessDenied") && strings.Contains(trimmed, "<Error") {
		return nil, errors.New("content CDN returned AccessDenied (content is region/IP restricted)")
	}
	if strings.HasPrefix(trimmed, "<?xml") || strings.HasPrefix(trimmed, "<Error") {
		return nil, fmt.Errorf("CDN returned an XML error instead of a playlist: %s", truncate(trimmed, 200))
	}
	if !strings.Contains(text, "#EXTM3U") {
		return nil, fmt.Errorf("not an HLS playlist: %s", truncate(trimmed, 120))
	}
	if strings.Contains(text, "#EXT-X-STREAM-INF") {
		variants := parseMaster(text, base)
		var videos []variantEntry
		for _, v := range variants {
			if !v.isAudio {
				videos = append(videos, v)
			}
		}
		if len(videos) == 0 {
			videos = variants
		}
		if len(videos) == 0 {
			return nil, errors.New("master playlist has no variants")
		}
		sort.SliceStable(videos, func(i, j int) bool { return videos[i].bw > videos[j].bw })
		chosen := videos[0]
		if wantLevel >= 0 && wantLevel < len(videos) {
			chosen = videos[wantLevel]
		}
		logf(q, "[hls] master: %d video variant(s); chosen: bw=%d res=%s", len(videos), chosen.bw, chosen.res)
		sd, err := resolveStream(c, chosen.uri, -1, q)
		if err != nil {
			return nil, err
		}
		if chosen.audio != "" {
			groups := parseMasterMedia(text, base)
			if a, ok := groups[chosen.audio]; ok {
				sd.audioURI = a.uri
			}
		}
		return sd, nil
	}
	segs, hints, err := parseMedia(text, base)
	if err != nil {
		return nil, err
	}
	return &streamDesc{segments: segs, hints: hints}, nil
}

func mustParse(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		fatal(err)
	}
	return u
}

// parseMedia parses a media playlist into ordered segments.
func parseMedia(text string, base *url.URL) ([]hlsSegment, mediaHints, error) {
	var segs []hlsSegment
	hints := mediaHints{}
	mediaSeq := uint64(0)
	var curKey hlsKey
	var curMap string
	var pendRange *byteRange
	pendDur := float64(-1)
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "#EXT-X-MEDIA-SEQUENCE:"):
			if n, err := strconv.ParseUint(line[len("#EXT-X-MEDIA-SEQUENCE:"):], 10, 64); err == nil {
				mediaSeq = n
			}
		case strings.HasPrefix(line, "#EXT-X-TARGETDURATION:"):
			if n, err := strconv.Atoi(line[len("#EXT-X-TARGETDURATION:"):]); err == nil {
				hints.targetDur = n
			}
		case strings.HasPrefix(line, "#EXT-X-MAP:"):
			a := splitAttrLine(line[len("#EXT-X-MAP:"):])
			if uri, ok := a["URI"]; ok {
				if u, err := base.Parse(uri); err == nil {
					curMap = u.String()
				}
			}
		case strings.HasPrefix(line, "#EXT-X-KEY:"):
			a := splitAttrLine(line[len("#EXT-X-KEY:"):])
			method := strings.ToUpper(a["METHOD"])
			if method == "NONE" {
				curKey = hlsKey{method: "NONE"}
				break
			}
			if method != "AES-128" && method != "SAMPLE-AES" {
				logf(false, "WARN: unknown EXT-X-KEY method %q", method)
				break
			}
			k := hlsKey{method: method}
			if uri, ok := a["URI"]; ok {
				if u, err := base.Parse(uri); err == nil {
					k.uri = u.String()
				}
			}
			if ivs, ok := a["IV"]; ok {
				ivs = strings.TrimSpace(ivs)
				ivs = strings.TrimPrefix(strings.TrimPrefix(ivs, "0x"), "0X")
				b, derr := hex.DecodeString(strings.TrimSpace(ivs))
				if derr != nil || len(b) != 16 {
					return nil, hints, fmt.Errorf("bad IV attribute %q", ivs)
				}
				k.iv = b
			}
			curKey = k
		case strings.HasPrefix(line, "#EXTINF:"):
			d := line[len("#EXTINF:"):]
			if i := strings.IndexByte(d, ','); i >= 0 {
				d = d[:i]
			}
			if f, err := strconv.ParseFloat(strings.TrimSpace(d), 64); err == nil {
				pendDur = f
			}
		case strings.HasPrefix(line, "#EXT-X-BYTERANGE:"):
			s := line[len("#EXT-X-BYTERANGE:"):]
			length, off := int64(0), int64(-1)
			var perr error
			if i := strings.IndexByte(s, '@'); i >= 0 {
				off, perr = strconv.ParseInt(s[i+1:], 10, 64)
				length, perr = strconv.ParseInt(s[:i], 10, 64)
			} else {
				length, perr = strconv.ParseInt(s, 10, 64)
			}
			if perr == nil {
				pendRange = &byteRange{length: length, offset: off}
			}
		case strings.HasPrefix(line, "#"):
			// other tags ignored
		default:
			u, err := base.Parse(line)
			if err != nil {
				return nil, hints, fmt.Errorf("bad segment URI %q: %v", line, err)
			}
			seg := hlsSegment{
				uri:      u.String(),
				key:      curKey,
				initURI:  curMap,
				byRange:  pendRange,
				mediaSeq: mediaSeq + uint64(len(segs)),
			}
			pendRange = nil
			if pendDur >= 0 {
				seg.dur = pendDur
			} else if hints.targetDur > 0 {
				seg.dur = float64(hints.targetDur) / 2
			}
			pendDur = -1
			segs = append(segs, seg)
			low := strings.ToLower(u.Path)
			switch {
			case strings.HasSuffix(low, ".ts"):
				hints.isFmp4 = false
			case strings.HasSuffix(low, ".m4s"), strings.HasSuffix(low, ".mp4"), strings.HasSuffix(low, ".m4v"):
				hints.isFmp4 = true
			case strings.HasSuffix(low, ".aac"), strings.HasSuffix(low, ".m4a"):
				hints.isFmp4 = true
				hints.audioOnly = true
			}
		}
	}
	return segs, hints, nil
}

// ---------------------------------------------------------------------------
// progress indicator
// ---------------------------------------------------------------------------

// progress draws a single-line download indicator:
//
//	Progress: [####----------------] 20% (200/1000, 12.3 MB)
//
// On a terminal every update rewrites the same line: the frame is written
// after a carriage return (\r), which puts the cursor back at the start of
// the current line, and is padded to the length of the previous frame so no
// leftovers survive when a line grows shorter. Updates end without '\n' -
// the line is only released once, when the run completes (finish) or is
// abandoned (end). os.Stdout is unbuffered in Go, so each write lands
// immediately, i.e. it is flushed as soon as it is issued.
//
// When stdout is not a terminal (pipe, file) '\r' tricks would just garble
// the output, so the indicator degrades to plain newline-terminated lines
// (like before), drawn for at most every 10th update. With -q it draws
// nothing at all, as before.
type progress struct {
	w       io.Writer // os.Stdout
	inline  bool      // update in place on a terminal
	quiet   bool      // -q: draw nothing at all
	done    bool      // no more updates (completed or abandoned)
	lastLen int       // length of the last in-place frame (pad-clearing)
	seq     int       // updates so far (throttle for the non-terminal path)
}

func newProgress(quiet bool) *progress {
	inline := false
	if fi, err := os.Stdout.Stat(); err == nil {
		inline = fi.Mode()&os.ModeCharDevice != 0 // console/tty, not a pipe
	}
	return &progress{w: os.Stdout, inline: inline, quiet: quiet}
}

// reset re-arms the indicator for another run (e.g. the audio rendition).
func (p *progress) reset() {
	p.done = false
	p.lastLen = 0
	p.seq = 0
}

// frame builds one indicator frame; ok is false when there is nothing to draw.
func (p *progress) frame(cur, total int, nbytes int64) (string, bool) {
	if p.quiet || total <= 0 || cur < 0 || cur > total {
		return "", false
	}
	const barW = 20
	filled := cur * barW / total
	return fmt.Sprintf("Progress: [%s%s] %d%% (%d/%d, %.1f MB)",
		strings.Repeat("#", filled), strings.Repeat("-", barW-filled),
		cur*100/total, cur, total, float64(nbytes)/(1024*1024)), true
}

// show reports progress: cur of total segments done, nbytes written so far.
// It never starts a new line; the in-place frame is overwritten by the next
// update or released by finish/end.
func (p *progress) show(cur, total int, nbytes int64) {
	line, ok := p.frame(cur, total, nbytes)
	if !ok {
		return
	}
	if !p.inline {
		// Not a terminal: plain throttled lines for readable piped output.
		// The final frame is left to finish(), which prints it even when
		// throttling skipped updates.
		if cur == total {
			return
		}
		p.seq++
		if p.seq%10 != 0 {
			return
		}
		fmt.Fprintf(p.w, "%s\n", line)
		return
	}
	if pad := p.lastLen - len(line); pad > 0 {
		line += strings.Repeat(" ", pad) // erase leftovers of a longer frame
	}
	fmt.Fprintf(p.w, "\r%s", line) // clears the line and overwrites it
	p.lastLen = len(line)
}

// finish closes a successful run: it guarantees the final 100% frame is on
// screen, then prints the one newline that releases the line.
func (p *progress) finish(cur, total int, nbytes int64) {
	if p.quiet || p.done {
		return
	}
	p.done = true
	line, ok := p.frame(cur, total, nbytes)
	if !p.inline {
		if ok { // piped output: final frame even when show() was throttled
			fmt.Fprintf(p.w, "%s\n", line)
		}
		return
	}
	if last := p.lastLen; last > 0 {
		if pad := last - len(line); pad > 0 {
			line += strings.Repeat(" ", pad)
		}
		fmt.Fprintf(p.w, "\r%s\n", line)
	} else if ok {
		fmt.Fprintf(p.w, "%s\n", line)
	}
	p.lastLen = 0
}

// end abandons the indicator on an error or interrupt. It does not draw
// another frame; it only releases the terminal line (newline) if a frame was
// actually hanging there, so the next output starts in column 0.
func (p *progress) end() {
	if p.quiet || p.done {
		return
	}
	p.done = true
	if p.inline && p.lastLen > 0 {
		fmt.Fprint(p.w, "\n")
	}
	p.lastLen = 0
}

// ---------------------------------------------------------------------------
// download + merge
// ---------------------------------------------------------------------------

func (c *client) loadKeys(segs []hlsSegment) (map[string][]byte, error) {
	uniq := map[string]bool{}
	for _, s := range segs {
		if s.key.method == "AES-128" && s.key.uri != "" && !uniq[s.key.uri] {
			uniq[s.key.uri] = true
		}
	}
	keys := map[string][]byte{}
	for uri := range uniq {
		body, err := c.get(uri, "*/*", 4)
		if err != nil {
			return nil, fmt.Errorf("fetch key %s: %v", uri, err)
		}
		if len(body) != 16 {
			return nil, fmt.Errorf("key from %s: %d bytes (expected 16)", uri, len(body))
		}
		keys[uri] = body
	}
	return keys, nil
}

func deriveKeyIV(k hlsKey, keys map[string][]byte, seq uint64) ([]byte, []byte, error) {
	kb, ok := keys[k.uri]
	if !ok {
		return nil, nil, fmt.Errorf("key %s not loaded", k.uri)
	}
	iv := k.iv
	if iv == nil {
		iv = make([]byte, 16)
		var b8 [8]byte
		binary.BigEndian.PutUint64(b8[:], seq)
		copy(iv[:8], b8[:])
	}
	return kb, iv, nil
}

func fetchSegment(c *client, s *hlsSegment, keys map[string][]byte, running *int64) ([]byte, error) {
	body, err := c.get(s.uri, "*/*", 4)
	if err != nil {
		return nil, err
	}
	data := body
	if s.byRange != nil {
		if s.byRange.offset < 0 {
			s.byRange.offset = *running
		}
		lo := s.byRange.offset
		hi := lo + s.byRange.length
		if lo < 0 || hi > int64(len(data)) {
			return nil, fmt.Errorf("byterange len=%d off=%d exceeds %d bytes", s.byRange.length, s.byRange.offset, len(data))
		}
		data = data[lo:hi]
		*running = hi
	}
	if s.key.method == "AES-128" {
		kb, iv, err := deriveKeyIV(s.key, keys, s.mediaSeq)
		if err != nil {
			return nil, err
		}
		data, err = aes128DecryptCBC(data, kb, iv)
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}

// mergeAndWrite downloads, decrypts, and merges segments in order into outPath.
func mergeAndWrite(c *client, sd *streamDesc, keys map[string][]byte, outPath string, conc int, q bool, prog *progress) (string, error) {
	segs := sd.segments
	prog.reset()
	defer prog.end() // on any early return: leave the terminal line clean
	format := formatOf(sd.hints.isFmp4, sd.hints.audioOnly)
	hasRanges := false
	for i := range segs {
		if segs[i].byRange != nil {
			hasRanges = true
		}
	}
	if hasRanges {
		logf(q, "[hls] byte-range playlist -> sequential mode")
	}
	if conc < 1 {
		conc = 1
	}
	if conc > 16 {
		conc = 16
	}
	f, err := os.Create(outPath)
	if err != nil {
		return format, err
	}
	defer f.Close()
	bufW := bufio.NewWriterSize(f, 1<<20)
	defer func() { _ = bufW.Flush() }()

	if format == "fmp4" && len(segs) > 0 && segs[0].initURI != "" {
		initData, err := c.get(segs[0].initURI, "*/*", 4)
		if err != nil {
			return format, fmt.Errorf("init segment (EXT-X-MAP): %v", err)
		}
		if _, err := bufW.Write(initData); err != nil {
			return format, err
		}
		logf(q, "[hls] init segment: %d bytes", len(initData))
	}

	type resItem struct {
		data []byte
		err  error
	}
	batch := conc
	if hasRanges {
		batch = 1
	}
	var running int64 // sequential byte-range offset tracker
	totalBytes := int64(0)
	for start := 0; start < len(segs); start += batch {
		end := start + batch
		if end > len(segs) {
			end = len(segs)
		}
		results := make([]resItem, end-start)
		if batch == 1 {
			results[0].data, results[0].err = fetchSegment(c, &segs[start], keys, &running)
		} else {
			var wg sync.WaitGroup
			for j := start; j < end; j++ {
				wg.Add(1)
				go func(j, ri int) {
					defer wg.Done()
					data, err := c.get(segs[j].uri, "*/*", 4)
					if err == nil && segs[j].key.method == "AES-128" {
						kb, iv, e2 := deriveKeyIV(segs[j].key, keys, segs[j].mediaSeq)
						if e2 != nil {
							err = e2
						} else {
							data, e2 = aes128DecryptCBC(data, kb, iv)
							if e2 != nil {
								err = e2
							}
						}
					}
					results[ri] = resItem{data: data, err: err}
				}(j, j-start)
			}
			wg.Wait()
		}
		for ri := range results {
			idx := start + ri
			if results[ri].err != nil {
				return format, fmt.Errorf("segment %d/%d (%s): %v", idx+1, len(segs), truncate(segs[idx].uri, 90), results[ri].err)
			}
			n, werr := bufW.Write(results[ri].data)
			totalBytes += int64(n)
			if werr != nil {
				return format, werr
			}
		}
		// In-place indicator on a terminal (\r overwrite, no newlines);
		// plain throttled lines when stdout is not a terminal.
		prog.show(end, len(segs), totalBytes)
	}
	prog.finish(len(segs), len(segs), totalBytes)
	logf(q, "merged %d segments, %.1f MB", len(segs), float64(totalBytes)/(1024*1024))
	return format, nil
}

func formatOf(isFmp4, audioOnly bool) string {
	if !isFmp4 {
		return "ts"
	}
	if audioOnly {
		return "aac"
	}
	return "fmp4"
}

func extOf(h mediaHints) string {
	switch {
	case h.isFmp4 && h.audioOnly:
		return ".m4a"
	case h.isFmp4:
		return ".mp4"
	default:
		return ".ts"
	}
}

// audioExtOf names the separate audio rendition file; ".aac" is used for raw
// ADTS because ffmpeg mux inputs are probed more reliably with that extension.
func audioExtOf(h mediaHints) string {
	switch {
	case h.isFmp4 && !h.audioOnly:
		return ".mp4"
	case h.isFmp4:
		return ".aac"
	default:
		return ".ts"
	}
}

// ---------------------------------------------------------------------------
// ffmpeg post-processing (optional)
// ---------------------------------------------------------------------------

func ffmpegBin() string {
	if runtime.GOOS == "windows" {
		return "ffmpeg.exe"
	}
	return "ffmpeg"
}

func ffmpegPresent() bool {
	_, err := exec.LookPath(ffmpegBin())
	return err == nil
}

func remux(src, dst string) error {
	var stderr bytes.Buffer
	cmd := exec.Command(ffmpegBin(), "-y", "-loglevel", "error", "-i", src, "-c", "copy", "-movflags", "+faststart", dst)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func remuxAudioVideo(videoSrc, audioSrc, dst string) error {
	var stderr bytes.Buffer
	cmd := exec.Command(ffmpegBin(), "-y", "-loglevel", "error",
		"-i", videoSrc, "-i", audioSrc,
		"-c", "copy", "-map", "0:v:0", "-map", "1:a:0",
		"-movflags", "+faststart", dst)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

// streamFail reports a stream/manifest fetch failure, adding a hint for the
// common region/IP-bound 403 case.
func streamFail(err error) {
	if strings.Contains(err.Error(), "HTTP 403") || strings.Contains(err.Error(), "AccessDenied") {
		pf("ERROR: content CDN returned 403. The signed URL is region/IP-bound;")
		pf("a normal residential IP in the streaming region (or VPN via -proxy) may be required.")
	}
	fatal(err)
}

func main() {
	log.SetFlags(0)
	var (
		outName = flag.String("o", "", "output base name (extension added automatically)")
		level   = flag.Int("level", -1, "variant index in the master playlist (-1=highest)")
		conc    = flag.Int("conc", 6, "parallel segment downloads (<=16)")
		noRemux = flag.Bool("no-remux", false, "skip ffmpeg even when available")
		keep    = flag.Bool("keep", false, "keep the intermediate file after successful remux")
		quiet   = flag.Bool("q", false, "quiet")
		base    = flag.String("base", "https://bunny-cdn-qbg-s6.testwave.cc/", "base URL used to resolve relative segment URIs from a local playlist file")
		proxy   = flag.String("proxy", "", "proxy for all requests, e.g. http://127.0.0.1:7890 or socks5://127.0.0.1:1080 (overrides system proxy env)")
		showVer = flag.Bool("version", false, "print version")
	)
	flag.Usage = func() {
		pf("Usage: shark [flags] [play.php URL | stream URL | playlist.m3u8 file | \"-\" for stdin]")
		pf("       (no argument -> uses ./playlist.m3u8; without -o the output is named <unix_time>.mp4)")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVer {
		pf("shark %s", version)
		return
	}
	args := flag.Args()
	var arg string
	switch n := len(args); {
	case n == 0:
		// No argument: default to ./playlist.m3u8.
		arg = "playlist.m3u8"
	case n == 1:
		arg = args[0]
	default:
		flag.Usage()
		os.Exit(2)
	}
	c := newClient(*proxy)
	prog := newProgress(*quiet)
	// Interrupts (Ctrl+C / SIGINT / SIGTERM): release the progress line so
	// the terminal is left in a clean state, then exit (128+n convention).
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		prog.end()
		os.Exit(130)
	}()

	var (
		sd    *streamDesc
		title string
	)
	if arg == "-" || !strings.Contains(arg, "://") {
		// Local playlist mode: read a captured .m3u8 from a file (or stdin)
		// and download the segments it lists. Relative segment URIs resolve
		// against -base (default: the known content CDN host).
		var (
			raw   []byte
			label string
		)
		if arg == "-" {
			b, rerr := io.ReadAll(os.Stdin)
			if rerr != nil {
				fatal(fmt.Errorf("reading stdin: %v", rerr))
			}
			raw, label = b, "stdin"
			title = "video"
		} else {
			b, rerr := os.ReadFile(arg)
			if rerr != nil {
				fatal(fmt.Errorf("reading playlist %q: %v", arg, rerr))
			}
			raw, label = b, arg
			stem := filepath.Base(arg)
			title = sanitize(strings.TrimSuffix(stem, filepath.Ext(stem)))
		}
		logf(*quiet, "local playlist: %s", label)
		text := string(raw)
		if !strings.Contains(text, "#EXTM3U") {
			fatal(fmt.Errorf("%s is not an HLS playlist (missing #EXTM3U)", label))
		}
		bu := *base
		if !strings.HasSuffix(bu, "/") {
			bu += "/"
		}
		baseU := mustParse(bu)
		switch {
		case strings.Contains(text, "#EXT-X-STREAM-INF"):
			// Master playlist file: pick a variant (a URL), then fetch its
			// media playlist over the network.
			variants := parseMaster(text, baseU)
			var videos []variantEntry
			for _, v := range variants {
				if !v.isAudio {
					videos = append(videos, v)
				}
			}
			if len(videos) == 0 {
				videos = variants
			}
			if len(videos) == 0 {
				fatal(errors.New("master playlist has no variants"))
			}
			sort.SliceStable(videos, func(i, j int) bool { return videos[i].bw > videos[j].bw })
			chosen := videos[0]
			if *level >= 0 && *level < len(videos) {
				chosen = videos[*level]
			}
			logf(*quiet, "[hls] master file: %d video variant(s); chosen: bw=%d res=%s", len(videos), chosen.bw, chosen.res)
			var derr error
			sd, derr = resolveStream(c, chosen.uri, -1, *quiet)
			if derr != nil {
				streamFail(derr)
			}
			if chosen.audio != "" {
				groups := parseMasterMedia(text, baseU)
				if a, ok := groups[chosen.audio]; ok {
					sd.audioURI = a.uri
				}
			}
		default:
			segs, hints, perr := parseMedia(text, baseU)
			if perr != nil {
				fatal(perr)
			}
			sd = &streamDesc{segments: segs, hints: hints}
			logf(*quiet, "local media playlist: %d segment(s) listed", len(segs))
		}
	} else {
		target, perr := url.Parse(arg)
		if perr != nil || target.Scheme == "" || target.Host == "" {
			fatal(fmt.Errorf("not a valid URL: %q", arg))
		}
		playURL := arg
		if strings.Contains(playURL, "play.php") {
			logf(*quiet, "fetching play.php ...")
			pageBytes, gerr := c.getPage(playURL, 2)
			if gerr != nil {
				fatal(gerr)
			}
			page := string(pageBytes)
			enc, derr := decryptEncFields(page, []byte(encKeyStr), []byte(encIVStr))
			if derr != nil {
				fatal(derr)
			}
			title = extractTitle(target, page)
			logf(*quiet, "video: %s", title)
			if enc.drmType != "" && enc.drmType != "clearkey" {
				logf(*quiet, "drm: %s keyId=%s", enc.drmType, truncate(enc.keyID, 20))
			}
			logf(*quiet, "stream: %s", truncate(enc.videoURL, 100))
			sd, derr = resolveStream(c, enc.videoURL, *level, *quiet)
			if derr != nil {
				streamFail(derr)
			}
		} else {
			// Direct stream URL mode: any non-play.php URL is treated as the
			// playlist URL itself (master or media) - handy for testing or when
			// the signed link is already known.
			if v := target.Query().Get("video_name"); v != "" {
				title = v
			} else {
				title = strings.TrimSuffix(filepath.Base(target.Path), filepath.Ext(target.Path))
			}
			logf(*quiet, "direct stream mode: %s", truncate(playURL, 100))
			var derr error
			sd, derr = resolveStream(c, playURL, *level, *quiet)
			if derr != nil {
				streamFail(derr)
			}
			title = sanitize(title)
		}
	}

	outBase := *outName
	if outBase == "" {
		// No -o: name the output after the current Unix timestamp
		// (extension is added later: .ts merged, .mp4 after remux).
		outBase = fmt.Sprintf("%d", time.Now().Unix())
	}
	outBase = sanitize(outBase)
	if d := filepath.Dir(outBase); d != "." && d != "" {
		if err := os.MkdirAll(d, 0o755); err != nil {
			fatal(err)
		}
	}

	logf(*quiet, "playlist: %d segment(s), target=%d fmp4=%v audioOnly=%v",
		len(sd.segments), sd.hints.targetDur, sd.hints.isFmp4, sd.hints.audioOnly)
	if len(sd.segments) == 0 {
		fatal(errors.New("playlist has no segments"))
	}
	skeys, err := c.loadKeys(sd.segments)
	if err != nil {
		fatal(err)
	}

	videoPart := outBase + ".part"
	videoFinal := outBase + extOf(sd.hints)
	logf(*quiet, "downloading %d segment(s) (%s stream) ...", len(sd.segments), formatOf(sd.hints.isFmp4, sd.hints.audioOnly))
	format, err := mergeAndWrite(c, sd, skeys, videoPart, *conc, *quiet, prog)
	if err != nil {
		os.Remove(videoPart)
		fatal(err)
	}
	if err := os.Rename(videoPart, videoFinal); err != nil {
		fatal(err)
	}

	var audioFinal string
	if sd.audioURI != "" {
		logf(*quiet, "fetching separate audio rendition ...")
		asd, aerr := resolveStream(c, sd.audioURI, -1, *quiet)
		if aerr != nil {
			logf(false, "WARN: audio rendition fetch failed: %v", aerr)
		} else {
			akeys, kerr := c.loadKeys(asd.segments)
			if kerr != nil {
				logf(false, "WARN: audio keys: %v", kerr)
			} else {
				audioPart := outBase + ".audio.part"
				audioFinal = outBase + audioExtOf(asd.hints)
				if _, merr := mergeAndWrite(c, asd, akeys, audioPart, *conc, *quiet, prog); merr != nil {
					os.Remove(audioPart)
					audioFinal = ""
					logf(false, "WARN: audio merge failed: %v", merr)
				} else if rerr := os.Rename(audioPart, audioFinal); rerr != nil {
					audioFinal = ""
				}
			}
		}
	}

	useFF := ffmpegPresent() && !*noRemux
	switch {
	case useFF && format == "ts":
		mp4 := outBase + ".mp4"
		logf(*quiet, "ffmpeg remux -> %s ...", mp4)
		if rerr := remux(videoFinal, mp4); rerr != nil {
			logf(false, "WARN: remux failed: %v; keeping %s", rerr, videoFinal)
			pf("saved: %s", videoFinal)
		} else {
			if !*keep {
				os.Remove(videoFinal)
			}
			if audioFinal != "" {
				muxed := outBase + ".mux.mp4"
				if aerr := remuxAudioVideo(mp4, audioFinal, muxed); aerr != nil {
					logf(false, "WARN: audio mux failed: %v", aerr)
					pf("saved: %s (video only; audio kept as %s)", mp4, audioFinal)
				} else {
					os.Remove(mp4)
					if !*keep {
						os.Remove(audioFinal)
					}
					pf("saved: %s (video+audio)", muxed)
				}
			} else {
				pf("saved: %s", mp4)
			}
		}
	case useFF && format == "fmp4":
		if audioFinal != "" {
			mp4 := outBase + ".mux.mp4"
			if aerr := remuxAudioVideo(videoFinal, audioFinal, mp4); aerr != nil {
				logf(false, "WARN: audio mux failed: %v", aerr)
				pf("saved: %s", videoFinal)
			} else {
				if !*keep {
					os.Remove(videoFinal)
					os.Remove(audioFinal)
				}
				pf("saved: %s (video+audio)", mp4)
			}
		} else if filepath.Ext(videoFinal) == ".mp4" {
			// optional metadata remux (faststart) for fragmented MP4 concat
			tmp := videoFinal + ".tmp.mp4"
			if rerr := remux(videoFinal, tmp); rerr == nil {
				os.Remove(videoFinal)
				os.Rename(tmp, videoFinal)
			} else {
				os.Remove(tmp)
			}
			pf("saved: %s", videoFinal)
		} else {
			pf("saved: %s", videoFinal)
		}
	default:
		pf("saved: %s", videoFinal)
		if audioFinal != "" {
			pf("saved: %s", audioFinal)
		}
	}
}
