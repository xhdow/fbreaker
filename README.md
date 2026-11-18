
# Project Overview

fbreaker is a command-line tool for batch encrypting/decrypting file headers to protect privacy.
It modifies file headers in-place (without copying the entire file), making files unusable while
preserving the ability to restore them with the correct password.

Current version: **V2 algorithm**

# Usage

```
fbreaker [-c N] [-b N] <encode|decode|info|clearmeta> <password> [dir_or_file]
```

## Options

| Flag | Description | Default | Range |
|------|-------------|---------|-------|
| `-c N` | Number of concurrent workers | 4 | >= 1 |
| `-b N` | Header bytes to encrypt | 512 | 28 ~ 65536 |
| `-h` | Show help | | |

## Commands

| Command | Description |
|---------|-------------|
| `encode` | Encrypt files/directories (in-place header modification, append metadata) |
| `decode` | Decrypt files/directories (restore header from metadata, recover original filename) |
| `info` | Show encryption status and metadata of a file |
| `clearmeta` | Remove trailing metadata only (keep encrypted header, no decryption) |

## Examples

```bash
# Encrypt directory (8 workers, 512 header bytes)
fbreaker -c 8 -b 512 encode 123456 ./data

# Decrypt directory
fbreaker -c 8 decode 123456 ./data

# View file encryption info
fbreaker info 123456 ./data/somefile

# Remove metadata only (keeps encrypted header)
fbreaker -c 8 clearmeta 123456 ./data
```

# V2 Algorithm

## Encryption

Encrypts a specified number of bytes at the file header, then writes the ciphertext back in-place.

- **Key derivation**: `MD5(password)` → AES-256 key
- **Cipher**: AES-GCM (authenticated encryption)
- **Nonce**: Random 12 bytes (stored in metadata, not in file header)
- **Default header size**: 512 bytes (if file is smaller, entire content is encrypted)
- **In-place**: Only the header bytes are overwritten; the rest of the file is untouched

## File Layout (after encryption)

```
[encrypted header: ndata bytes][rest of file...][cryptinfo][ncryptinfo]
```

### cryptinfo structure (write order)

| Field | Size | Description |
|-------|------|-------------|
| ndata | 4 bytes | Number of encrypted header bytes |
| nonce | 12 bytes | AES-GCM nonce |
| tag | 16 bytes | AES-GCM authentication tag |
| md5 | 16 bytes | MD5 of the password (for quick verification) |
| fname | nfname bytes | Original filename (UTF-8, bit-inverted) |
| nfname | 4 bytes | Original filename length |
| magic | 4 bytes | "XYXY" (V2 version marker) |
| padding | 0-255 bytes | Random padding (tail length camouflage) |
| npadding | 4 bytes | Number of padding bytes |

The last 4 bytes of the file are always `ncryptinfo` (total cryptinfo length),
allowing metadata location without scanning.

## Encrypted Filename

After encryption, filenames are randomized to 16-hex-char strings with no extension.
Example: `3a7f9c2e1b8d4f60`

# Safety Features

- **Prevent double encryption**: `encode` detects already-encrypted files and skips them
- **Prevent accidental decryption**: `decode` detects unencrypted files and skips them
- **Password confirmation**: `encode` prompts for password re-entry before processing
- **Password verification**: `decode` verifies MD5 before attempting decryption
- **Concurrency safe**: Atomic counters, goroutine-based parallel processing
