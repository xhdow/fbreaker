// fbreaker —— File header batch encrypt/decrypt tool (V2 algorithm)
//
// Commands:
//
//	encode     Encrypt files/directories (in-place header modification, append metadata)
//	decode     Decrypt files/directories (restore header from metadata, recover original filename)
//	info       Show encryption status and metadata of a file
//	clearmeta  Remove trailing metadata only (keep encrypted header, no decryption)
//
// Usage:
//
//	fbreaker [-c N] [-b N] <encode|decode|info|clearmeta> <password> [dir_or_file]
//
// V2 algorithm: see README.md / README_CN.md
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

// ---------------------------------------------------------------------------
// Constants and types
// ---------------------------------------------------------------------------

const (
	// MagicV2 is the V2 version marker, fixed 4 bytes at the end of an encrypted file.
	MagicV2 = "XYXY"

	// DefaultHeaderBytes is the default number of header bytes to encrypt.
	// Note: if the file is smaller than this, the entire file content is encrypted.
	DefaultHeaderBytes = 512

	// NonceSize is the AES-GCM nonce length (NIST recommended 12 bytes).
	NonceSize = 12

	// GCMTagSize is the AES-GCM authentication tag length.
	GCMTagSize = 16

	// MaxPaddingBytes is the maximum random padding length (0-255).
	MaxPaddingBytes = 255

	// MaxMetaSize is the maximum metadata length (guard against corrupt/malicious files).
	MaxMetaSize = 1 << 20 // 1 MiB

	// MaxFnameLen is the maximum original filename length.
	MaxFnameLen = 4096

	// MinHeaderBytes is the minimum file header size needed for encryption (nonce + tag).
	MinHeaderBytes = NonceSize + GCMTagSize

	// MaxHeaderBytes is the maximum allowed header size via -b flag.
	MaxHeaderBytes = 64 * 1024 // 64 KiB
)

// EncryptFunc is the per-file processing callback.
// Returns (err, skipped): skipped=true means the file was skipped due to state mismatch (not an error).
type EncryptFunc func(path string, pwd string, maxHeader int) (error, bool)

// MetaV2 represents the trailing metadata of an encrypted file (V2).
//
// File layout (after encryption):
//
//	[encrypted header: ndata bytes][rest of file...][cryptinfo][ncryptinfo]
//
// cryptinfo structure (write order):
//
//	ndata     4B    number of encrypted header bytes
//	nonce     12B   AES-GCM nonce
//	tag       16B   AES-GCM authentication tag
//	md5       16B   MD5 of the password (for quick password verification)
//	fname     nfname B  original filename (UTF-8, bit-inverted)
//	nfname    4B    original filename length
//	magic     4B    "XYXY"
//	padding   0~255B  random padding
//	npadding  4B    number of padding bytes
//
// The last 4 bytes of the file are always ncryptinfo (total cryptinfo length),
// so metadata can be located without scanning.
type MetaV2 struct {
	NData    int    // Number of encrypted header bytes
	Nonce    []byte // AES-GCM nonce (NonceSize bytes)
	Tag      []byte // AES-GCM authentication tag (GCMTagSize bytes)
	Password []byte // MD5 of the password (16 bytes)
	OrigName string // Original filename (decoded from bit-inverted form)
	Padding  []byte // Random padding
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

// StatCounters is a concurrency-safe statistics counter.
type StatCounters struct {
	Total   atomic.Uint64 // Total regular files scanned
	Success atomic.Uint64 // Successfully processed files
	Skipped atomic.Uint64 // Skipped files (state mismatch, too small, etc.)
	Failed  atomic.Uint64 // Failed files
}

// ---------------------------------------------------------------------------
// Metadata encode/decode
// ---------------------------------------------------------------------------

// invertBytes bit-inverts a byte slice (encoding for fname to avoid plaintext filename).
func invertBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = ^v
	}
	return out
}

// buildMeta serializes metadata into the cryptinfo byte sequence (without the trailing length field).
func buildMeta(meta *MetaV2) []byte {
	var buf []byte

	// ndata: 4 bytes, big-endian
	ndata := make([]byte, 4)
	binary.BigEndian.PutUint32(ndata, uint32(meta.NData))
	buf = append(buf, ndata...)

	// nonce: NonceSize bytes
	buf = append(buf, meta.Nonce...)

	// tag: GCMTagSize bytes
	buf = append(buf, meta.Tag...)

	// md5: 16 bytes
	buf = append(buf, meta.Password...)

	// fname: bit-inverted original filename
	fname := invertBytes([]byte(meta.OrigName))
	buf = append(buf, fname...)

	// nfname: 4 bytes
	nfname := make([]byte, 4)
	binary.BigEndian.PutUint32(nfname, uint32(len(meta.OrigName)))
	buf = append(buf, nfname...)

	// magic: "XYXY"
	buf = append(buf, MagicV2...)

	// padding + npadding
	buf = append(buf, meta.Padding...)
	np := make([]byte, 4)
	binary.BigEndian.PutUint32(np, uint32(len(meta.Padding)))
	buf = append(buf, np...)

	return buf
}

// parseMeta deserializes metadata from a cryptinfo byte sequence.
// maxHeader is the maximum allowed ndata value (from -b flag, for validation).
func parseMeta(cryptinfo []byte, maxHeader int) (*MetaV2, error) {
	// Read tail fields in reverse:
	// [npadding 4B][padding npadding][magic 4B][nfname 4B][fname][tag 16B][nonce 12B][ndata 4B]
	if len(cryptinfo) < 4 {
		return nil, errors.New("metadata too short")
	}
	npadding := int(binary.BigEndian.Uint32(cryptinfo[len(cryptinfo)-4:]))
	if npadding > MaxPaddingBytes || npadding < 0 {
		return nil, fmt.Errorf("invalid padding length: %d", npadding)
	}
	// Strip trailing npadding(4B) and padding(npadding B)
	rest := cryptinfo[:len(cryptinfo)-4]
	if len(rest) < npadding {
		return nil, errors.New("metadata truncated (padding)")
	}
	padding := rest[len(rest)-npadding:]
	rest = rest[:len(rest)-npadding]

	// magic (before padding)
	if len(rest) < 4 || string(rest[len(rest)-4:]) != MagicV2 {
		return nil, errors.New("V2 magic mismatch")
	}
	rest = rest[:len(rest)-4]

	// nfname
	if len(rest) < 4 {
		return nil, errors.New("metadata truncated (nfname)")
	}
	nfname := int(binary.BigEndian.Uint32(rest[len(rest)-4:]))
	if nfname < 0 || nfname > MaxFnameLen || len(rest) < 4+nfname {
		return nil, fmt.Errorf("invalid original filename length: %d", nfname)
	}
	rest = rest[:len(rest)-4]

	// fname (bit-inverted, decode)
	fnameBytes := rest[len(rest)-nfname:]
	rest = rest[:len(rest)-nfname]

	// ndata + nonce + tag + md5 (in buildMeta write order)
	if len(rest) < 4+NonceSize+GCMTagSize+16 {
		return nil, errors.New("metadata truncated (ndata/nonce/tag/md5)")
	}
	ndata := int(binary.BigEndian.Uint32(rest[:4]))
	nonce := rest[4 : 4+NonceSize]
	tag := rest[4+NonceSize : 4+NonceSize+GCMTagSize]
	password := rest[4+NonceSize+GCMTagSize : 4+NonceSize+GCMTagSize+16]

	meta := &MetaV2{
		NData:    ndata,
		Nonce:    append([]byte{}, nonce...),
		Tag:      append([]byte{}, tag...),
		Password: append([]byte{}, password...),
		OrigName: string(invertBytes(fnameBytes)),
		Padding:  append([]byte{}, padding...),
	}
	if meta.NData < MinHeaderBytes || meta.NData > maxHeader {
		return nil, fmt.Errorf("invalid encrypted length: %d", meta.NData)
	}
	return meta, nil
}

// readMetaAt tries to read metadata at file offset off.
// Returns (meta, ok): ok=false means the file is not encrypted or metadata is corrupt.
func readMetaAt(f *os.File, off int64, maxHeader int) (*MetaV2, bool) {
	if off < 8 { // at least ncryptinfo(4) + magic(4)
		return nil, false
	}
	// Read last 4 bytes to get ncryptinfo
	if _, err := f.Seek(off-4, io.SeekStart); err != nil {
		return nil, false
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, false
	}
	ncryptinfo := int(binary.BigEndian.Uint32(buf))
	if ncryptinfo <= 0 || ncryptinfo > MaxMetaSize || off-int64(ncryptinfo)-4 < 0 {
		return nil, false
	}
	// Read the cryptinfo body
	if _, err := f.Seek(off-int64(ncryptinfo)-4, io.SeekStart); err != nil {
		return nil, false
	}
	cryptinfo := make([]byte, ncryptinfo)
	if _, err := io.ReadFull(f, cryptinfo); err != nil {
		return nil, false
	}
	meta, err := parseMeta(cryptinfo, maxHeader)
	if err != nil {
		return nil, false
	}
	return meta, true
}

// tryReadMeta opens a file and tries to read its trailing metadata.
// Returns (meta, ok, err): ok=false means not encrypted or metadata corrupt.
func tryReadMeta(path string, maxHeader int) (*MetaV2, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if st.IsDir() {
		return nil, false, errors.New("is a directory")
	}
	meta, ok := readMetaAt(f, st.Size(), maxHeader)
	return meta, ok, nil
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt
// ---------------------------------------------------------------------------

// randInt returns a cryptographically secure random integer in [0, max).
func randInt(max int) (int, error) {
	if max <= 0 {
		return 0, nil
	}
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint32(b) % uint32(max)), nil
}

// newGCM creates an AES-GCM instance from the password. Key = MD5(password).
func newGCM(pwd string) (cipher.AEAD, error) {
	key := md5.Sum([]byte(pwd))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// randFileName generates a random 16-hex-char filename (no extension) for camouflage.
func randFileName() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// encryptFile encrypts a file with V2 (in-place, no full file copy).
//
// Steps:
//  1. Validate file header size, read data to encrypt
//  2. AES-GCM encrypt (key = MD5(pwd), random nonce)
//  3. Write ciphertext back in-place (same length, no overwrite of following content)
//  4. Append encrypted metadata + length field to the tail
//  5. Randomize filename
func encryptFile(path string, pwd string, maxHeader int) (error, bool) {
	_, ok, err := tryReadMeta(path, maxHeader)
	if err != nil {
		return err, false
	}
	if ok {
		return fmt.Errorf("already encrypted, skipped"), true
	}

	fi, err := os.Stat(path)
	if err != nil {
		return err, false
	}
	size := fi.Size()
	if size < MinHeaderBytes {
		return fmt.Errorf("file too small to encrypt (need >= %d bytes)", MinHeaderBytes), false
	}

	ndata := maxHeader
	if size < int64(ndata) {
		ndata = int(size)
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err, false
	}
	defer f.Close()

	// Read file header
	header := make([]byte, ndata)
	if _, err := f.ReadAt(header, 0); err != nil {
		return fmt.Errorf("failed to read header: %w", err), false
	}

	// Generate nonce and encrypt
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err, false
	}
	gcm, err := newGCM(pwd)
	if err != nil {
		return err, false
	}
	// Seal output: nonce(12) + ciphertext(ndata) + tag(16)
	sealed := gcm.Seal(nonce, nonce, header, nil)
	ciphertext := sealed[NonceSize : NonceSize+ndata] // pure ciphertext, length = ndata
	tag := sealed[NonceSize+ndata:]                   // GCM auth tag

	// Write pure ciphertext back in-place (length = ndata, doesn't overwrite following content)
	if _, err := f.WriteAt(ciphertext, 0); err != nil {
		return fmt.Errorf("failed to write ciphertext: %w", err), false
	}

	// Build and append metadata
	pwdMD5 := md5.Sum([]byte(pwd))
	m := &MetaV2{
		NData:    ndata,
		Nonce:    nonce,
		Tag:      tag,
		Password: pwdMD5[:],
		OrigName: filepath.Base(path),
	}
	// Random padding 0~MaxPaddingBytes bytes (camouflage for tail length)
	padLen, err := randInt(MaxPaddingBytes + 1)
	if err != nil {
		return err, false
	}
	m.Padding = make([]byte, padLen)
	if padLen > 0 {
		if _, err := rand.Read(m.Padding); err != nil {
			return err, false
		}
	}
	cryptinfo := buildMeta(m)
	ncryptinfo := make([]byte, 4)
	binary.BigEndian.PutUint32(ncryptinfo, uint32(len(cryptinfo)))

	if _, err := f.WriteAt(cryptinfo, size); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err), false
	}
	if _, err := f.WriteAt(ncryptinfo, size+int64(len(cryptinfo))); err != nil {
		return fmt.Errorf("failed to write metadata length: %w", err), false
	}
	f.Close()

	// Randomize filename
	newName, err := randFileName()
	if err != nil {
		return err, false
	}
	return os.Rename(path, filepath.Join(filepath.Dir(path), newName)), false
}

// decryptFile decrypts an encrypted file (in-place restore).
//
// Steps:
//  1. Read trailing metadata and verify password MD5
//  2. Restore the encrypted header
//  3. Truncate trailing metadata
//  4. Recover original filename
func decryptFile(path string, pwd string, maxHeader int) (error, bool) {
	meta, ok, err := tryReadMeta(path, maxHeader)
	if err != nil {
		return err, false
	}
	if !ok {
		return fmt.Errorf("not encrypted, skipped."), true
	}
	pwdMD5 := md5.Sum([]byte(pwd))
	if string(meta.Password) != string(pwdMD5[:]) {
		return fmt.Errorf("wrong password: %s", path), false
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err, false
	}
	defer f.Close()

	// Restore file header
	gcm, err := newGCM(pwd)
	if err != nil {
		return err, false
	}
	// Read pure ciphertext (length = ndata), append tag from metadata for GCM Open
	ciphertext := make([]byte, meta.NData)
	if _, err := f.ReadAt(ciphertext, 0); err != nil {
		return fmt.Errorf("failed to read ciphertext: %w", err), false
	}
	// GCM Open needs ciphertext || tag
	ctWithTag := append(ciphertext, meta.Tag...)
	plain, err := gcm.Open(nil, meta.Nonce, ctWithTag, nil)
	if err != nil {
		return fmt.Errorf("decryption failed (data corrupt or wrong password): %w", err), false
	}
	if _, err := f.WriteAt(plain, 0); err != nil {
		return fmt.Errorf("failed to write plaintext: %w", err), false
	}

	// Truncate trailing metadata
	fi, err := f.Stat()
	if err != nil {
		return err, false
	}
	truncateTo := fi.Size() - int64(len(buildMeta(meta))) - 4
	if truncateTo < 0 {
		return errors.New("metadata length abnormal"), false
	}
	if err := f.Truncate(truncateTo); err != nil {
		return fmt.Errorf("truncate failed: %w", err), false
	}
	f.Close()

	// Recover original filename
	newPath := filepath.Join(filepath.Dir(path), meta.OrigName)
	if _, err := os.Stat(newPath); err == nil {
		return fmt.Errorf("target filename already exists, not renamed: %s", newPath), false
	}
	return os.Rename(path, newPath), false
}

// clearMeta removes only the trailing metadata (keeps encrypted header, no decryption).
func clearMeta(path string, pwd string, maxHeader int) (error, bool) {
	meta, ok, err := tryReadMeta(path, maxHeader)
	if err != nil {
		return err, false
	}
	if !ok {
		return fmt.Errorf("not encrypted, skipped."), true
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err, false
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err, false
	}
	truncateTo := fi.Size() - int64(len(buildMeta(meta))) - 4
	if truncateTo < 0 {
		return errors.New("metadata length abnormal"), false
	}
	return f.Truncate(truncateTo), false
}

// showInfo prints the encryption status and metadata of a file.
func showInfo(path string, pwd string, maxHeader int) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("is a directory, please specify a file: %s", path)
	}

	meta, ok, err := tryReadMeta(path, maxHeader)
	if err != nil {
		return err
	}

	fmt.Printf("File:      %s\n", path)
	fmt.Printf("Size:      %d bytes\n", st.Size())
	if !ok {
		fmt.Println("Status:    Not encrypted (or metadata corrupt)")
		return nil
	}
	fmt.Println("Status:    Encrypted (V2)")
	fmt.Printf("Version:   XYXY\n")
	fmt.Printf("Header:    %d bytes encrypted\n", meta.NData)
	fmt.Printf("OrigName:  %s\n", meta.OrigName)
	fmt.Printf("PwdMD5:    %X\n", meta.Password)
	if pwd != "" {
		pwdMD5 := md5.Sum([]byte(pwd))
		if string(meta.Password) == string(pwdMD5[:]) {
			fmt.Println("Password:  Correct")
		} else {
			fmt.Println("Password:  Wrong")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Directory traversal (concurrent)
// ---------------------------------------------------------------------------

// walkFiles recursively collects all regular files under root, then processes them concurrently.
// workers is the concurrency level (minimum 1).
func walkFiles(root string, workers int, fn EncryptFunc, pwd string, maxHeader int, counters *StatCounters) error {
	if workers < 1 {
		workers = 1
	}

	// Collect all regular file paths
	var paths []string
	var visit func(dir string) error
	visit = func(dir string) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			fmt.Printf("[walk error] %v: %v\n", dir, err)
			counters.Failed.Add(1)
			return nil
		}
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			if e.IsDir() {
				if err := visit(p); err != nil {
					return err
				}
			} else if e.Type().IsRegular() {
				paths = append(paths, p)
			}
		}
		return nil
	}
	if err := visit(root); err != nil {
		return err
	}
	counters.Total.Store(uint64(len(paths)))

	// Concurrent processing
	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				err, skipped := fn(p, pwd, maxHeader)
				if skipped {
					fmt.Printf("[skip] %s: %v\n", p, err)
					counters.Skipped.Add(1)
				} else if err != nil {
					fmt.Printf("[fail] %s: %v\n", p, err)
					counters.Failed.Add(1)
				} else {
					counters.Success.Add(1)
				}
			}
		}()
	}
	for _, p := range paths {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	return nil
}

// printCounters prints the statistics summary.
func printCounters(c *StatCounters) {
	fmt.Println("----------------------------------------")
	fmt.Printf("Scanned:   %d\n", c.Total.Load())
	fmt.Printf("Succeeded: %d\n", c.Success.Load())
	fmt.Printf("Skipped:   %d\n", c.Skipped.Load())
	fmt.Printf("Failed:    %d\n", c.Failed.Load())
	fmt.Println("----------------------------------------")
}

// ---------------------------------------------------------------------------
// Password confirmation
// ---------------------------------------------------------------------------

// promptPassword prompts the user to re-enter the password for confirmation (encode only).
// Returns true if passwords match.
func promptPassword(pwd string) bool {
	fmt.Print("Re-enter password to confirm: ")
	reader := bufio.NewReader(os.Stdin)
	confirm, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	confirm = strings.TrimRight(confirm, "\r\n")
	return confirm == pwd
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func usage() {
	fmt.Println("fbreaker - File header batch encrypt/decrypt tool (V2)")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  fbreaker [-c N] [-b N] <encode|decode|info|clearmeta> <password> [dir_or_file]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -c N    Number of concurrent workers (default 4, minimum 1)")
	fmt.Println("  -b N    Header bytes to encrypt (default 512, max 65536)")
	fmt.Println("  -h      Show this help")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  encode     Encrypt files/directories")
	fmt.Println("  decode     Decrypt files/directories")
	fmt.Println("  info       Show encryption status and metadata of a file")
	fmt.Println("  clearmeta  Remove trailing metadata only")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  fbreaker -c 8 -b 512 encode 123456 ./data")
	fmt.Println("  fbreaker -c 8 decode 123456 ./data")
	fmt.Println("  fbreaker info 123456 ./data/somefile")
}

// resolveFn maps a command name to its handler function.
func resolveFn(cmd string) (EncryptFunc, bool) {
	switch cmd {
	case "encode":
		return encryptFile, true
	case "decode":
		return decryptFile, true
	case "clearmeta":
		return clearMeta, true
	}
	return nil, false
}

func main() {
	workers := flag.Int("c", 4, "concurrent workers (minimum 1)")
	maxHeader := flag.Int("b", DefaultHeaderBytes, fmt.Sprintf("header bytes to encrypt (default %d, max %d)", DefaultHeaderBytes, MaxHeaderBytes))
	flag.Usage = usage
	flag.Parse()

	if *workers < 1 {
		*workers = 1
	}
	if *maxHeader < MinHeaderBytes || *maxHeader > MaxHeaderBytes {
		fmt.Fprintf(os.Stderr, "Error: -b must be between %d and %d\n", MinHeaderBytes, MaxHeaderBytes)
		os.Exit(1)
	}

	args := flag.Args()
	if len(args) < 1 {
		usage()
		return
	}

	cmd := args[0]

	// info command: fbreaker info <password> <file>
	if cmd == "info" {
		if len(args) < 3 {
			usage()
			return
		}
		if err := showInfo(args[2], args[1], *maxHeader); err != nil {
			fmt.Fprintf(os.Stderr, "[error] %v\n", err)
			os.Exit(1)
		}
		return
	}

	fn, ok := resolveFn(cmd)
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		usage()
		return
	}

	if len(args) < 3 {
		usage()
		return
	}
	pwd := args[1]
	target := args[2]

	// Password confirmation for encode
	if cmd == "encode" {
		if !promptPassword(pwd) {
			fmt.Fprintln(os.Stderr, "Password confirmation failed. Aborted.")
			os.Exit(1)
		}
		fmt.Println()
	}

	fi, err := os.Stat(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}
	if !fi.IsDir() {
		// Single file mode
		if err, skipped := fn(target, pwd, *maxHeader); err != nil {
			if skipped {
				fmt.Printf("[skip] %s: %v\n", target, err)
			} else {
				fmt.Fprintf(os.Stderr, "[fail] %s: %v\n", target, err)
				os.Exit(1)
			}
		} else {
			fmt.Println("Done.")
		}
		return
	}

	// Directory mode
	fmt.Printf("Command: %s | Target: %s | Workers: %d | Header: %d bytes\n", cmd, target, *workers, *maxHeader)
	counters := &StatCounters{}
	if err := walkFiles(target, *workers, fn, pwd, *maxHeader, counters); err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}
	printCounters(counters)
}
