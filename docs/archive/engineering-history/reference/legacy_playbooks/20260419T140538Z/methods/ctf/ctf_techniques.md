# CTF Techniques Reference

Techniques specific to CTF challenges: steganography, encoding/cipher identification,
binary RE basics, crypto, and OSINT. For web/exploitation see dedicated playbooks.

---

## 1. Steganography

### Universal First Pass (run on every challenge file)
```bash
file challenge.*              # true file type (ignores extension)
binwalk challenge.png         # embedded files
binwalk -e challenge.png      # extract embedded files to _challenge.png.extracted/
exiftool challenge.png        # metadata (GPS, comments, author, creation tool)
strings challenge.png | grep -iE "flag|ctf|key|pass|secret|{.*}"
xxd challenge.png | head -20  # raw hex header
```

### Image Steganography
```bash
# LSB (least significant bit) — most common CTF technique
zsteg challenge.png           # automated LSB detection (PNG/BMP)
# Output: b1,r,lsb,xy → extra text found in red channel LSB

# stegsolve (GUI Java tool) — bit plane viewer
java -jar stegsolve.jar       # open file → cycle through bit planes
# Look for: hidden image in lower bit planes, color channel isolation

# steghide — password-protected hiding in JPEG/BMP/WAV
steghide extract -sf challenge.jpg              # no password
steghide extract -sf challenge.jpg -p password  # with password
steghide info challenge.jpg                     # check if data hidden

# stegseek — fast steghide brute force
stegseek challenge.jpg wordlists/rockyou.txt.gz

# outguess
outguess -r challenge.jpg output.txt

# OpenStego (Java GUI for spatial domain + DCT)
```

### Audio Steganography
```bash
# Spectrogram analysis (most common — hidden image in frequency domain)
# Audacity: Import audio → View → Spectrogram (or Ctrl+Shift+U on track)
# Look for: image/text visible in spectrogram, especially at edges of frequency range

# Alternate tool: Sonic Visualiser
# Plugin: Spectrum — select "All Channels" view

# SSTV (Slow Scan Television) — image encoded in audio
# Install: apt install qsstv
# Or: use rx-sstv, decode with MultiPSK

# MP3/WAV metadata
exiftool audio.mp3
id3v2 -l audio.mp3

# Data at end of file (append after audio data)
binwalk audio.wav
xxd audio.wav | tail -20
```

### Archive / File Carving
```bash
# Carve files from binary blob
foremost -i challenge.bin -o output/
# Detects: JPEG, PNG, GIF, ZIP, PDF, EXE, etc.

# ZIP inspection
unzip -l archive.zip          # list contents
unzip -p archive.zip          # extract to stdout
zipnote archive.zip           # view/edit comments
zip2john archive.zip > hash.txt && john hash.txt --wordlist=rockyou.txt

# Password brute
fcrackzip -u -D -p wordlists/rockyou.txt.gz challenge.zip
hashcat -m 13600 hash.txt wordlists/rockyou.txt.gz -O   # ZIP AES

# RAR
john hash.txt (rar2john first)
hashcat -m 13000 (RAR5) or -m 23700

# 7z
7z2john archive.7z > hash.txt
hashcat -m 11600 hash.txt wordlist
```

### PDF Steganography
```bash
pdf-parser.py challenge.pdf   # parse structure
pdfextract challenge.pdf      # extract embedded objects
pdfimages -all challenge.pdf output_prefix  # extract images
strings challenge.pdf | grep -i flag
# Check embedded JavaScript: streams may contain hidden data
```

### Standard Tool Chain Order
```
1. file → 2. binwalk → 3. exiftool → 4. strings → 5. foremost
→ 6. stegsolve (image) / spectrogram (audio) → 7. zsteg (PNG) / steghide (JPEG)
→ 8. stegseek (brute if steghide) → 9. outguess
```

---

## 2. Encoding / Cipher Identification

### Quick Identification Guide
| Pattern | Encoding | Decode |
|---------|----------|--------|
| `[A-Za-z0-9+/=]` (length multiple of 4) | Base64 | `base64 -d` |
| `[A-Z2-7=]` (uppercase, 2-7, padding) | Base32 | `base32 -d` |
| `[1-9A-HJ-NP-Za-km-z]` (no 0OIl) | Base58 | `python3 -c "import base58; print(base58.b58decode(s))"` |
| `[0-9a-f]` only (even length) | Hex | `xxd -r -p` or `echo "hex" | python3 -c "import sys,binascii; print(binascii.unhexlify(sys.stdin.read().strip()))"` |
| `[01 ]` only | Binary | `python3 -c "print(chr(int('01001000',2)))"` (per byte) |
| `.- / ` pattern | Morse | Decode table; spaces=letter, `/`=word |
| All uppercase alpha, uniform frequency | Caesar | Brute all 26 shifts |
| All uppercase, repeating key length | Vigenère | dcode.fr (auto key) |
| `%XX` hex in URL | URL encoding | `python3 -c "import urllib.parse; print(urllib.parse.unquote('...'))"` |
| `&#NNN;` or `&#xHH;` | HTML entities | Browser / CyberChef |
| `=?UTF-8?B?BASE64?=` | MIME encoded | `python3 -c "import email.header; print(email.header.decode_header('...')[0][0])"` |

### Shell Decode One-Liners
```bash
# Base64
echo "SGVsbG8=" | base64 -d

# Hex
echo "48656c6c6f" | xxd -r -p

# ROT13
echo "Uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# URL decode
python3 -c "import urllib.parse; print(urllib.parse.unquote('%48%65%6c%6c%6f'))"

# Caesar brute force (all 26 shifts)
python3 -c "
s='KHOOR'
for i in range(26):
    print(i, ''.join(chr((ord(c)-65+i)%26+65) if c.isupper() else
                     chr((ord(c)-97+i)%26+97) if c.islower() else c for c in s))"
```

### Vigenère / Polyalphabetic
```bash
# Online: https://www.dcode.fr/vigenere-cipher  (use Automatic Decryption)
# Or: https://www.guballa.de/vigenere-solver
# Key length hint: index of coincidence analysis
python3 -c "
from itertools import cycle
ct = 'LXFOPVEFRNHR'
key = 'LEMON'
print(''.join(chr((ord(c)-ord(k))%26+65) for c,k in zip(ct,cycle(key))))"
```

### Identification Tools
- **CyberChef** (local or online): "Magic" operation → auto-detects encoding chain
- **dcode.fr** — cipher identification + automatic solvers for 200+ ciphers
- **boxentriq.com/code-breaking** — frequency analysis, cipher identification
- **Ciphey** (CLI): `ciphey -t "ENCODED_STRING"` → automated decode chain

---

## 3. Binary RE Basics (CTF)

### Static Analysis — First Steps
```bash
file binary                           # ELF/PE/Mach-O, arch, stripped?
strings -n 8 binary | grep -iE "flag|ctf|key|pass|secret|\{.*\}"
strings -n 8 binary | less           # browse all strings
objdump -d binary | head -100        # disassembly quick look
objdump -d binary | grep -A5 "cmp\|strcmp\|strncmp"  # find comparisons
readelf -s binary                    # symbol table (function names if not stripped)
nm binary                            # symbols
checksec --file=binary               # security mitigations (PIE, NX, stack canary)
```

### Dynamic Analysis
```bash
# ltrace — library call trace (gold for CTF)
ltrace ./binary                      # shows strcmp(input, "secret") ← flag often visible
ltrace -s 100 ./binary               # increase string length (default 32)

# strace — syscall trace
strace ./binary                      # open(), read(), write() calls
strace -e trace=open,read ./binary   # filter to file operations

# Run with input
echo "test_input" | ltrace ./binary
printf '%s\n' "guess" | ltrace ./binary
```

### GDB Workflow
```bash
gdb ./binary
(gdb) info functions          # list all functions
(gdb) disas main              # disassemble main
(gdb) break main              # breakpoint at main
(gdb) break *0x0040123a       # breakpoint at address
(gdb) run                     # start
(gdb) nexti                   # step one instruction
(gdb) info registers          # all registers
(gdb) x/s $rdi                # examine string at RDI
(gdb) x/20x $rsp              # examine stack
(gdb) x/s 0x402010            # examine string at address
(gdb) set $rax = 1            # modify register
(gdb) continue
```

### GDB peda/pwndbg (enhanced)
```bash
gdb-peda ./binary             # PEDA — pattern, checksec, context
# In peda:
pattern create 100            # generate cyclic pattern for overflow
pattern offset 0x41614141     # find offset from crash EIP/RIP
checksec                      # security mitigations
vmmap                         # memory map
```

### Ghidra Workflow
```
1. New Project → Import File → drag binary
2. Analysis → Auto Analyze → default options
3. Symbol Tree → Functions → main
4. Decompiler panel shows C-like pseudocode
5. Follow function calls: double-click
6. Find flag check: look for strcmp, strncmp, memcmp calls
7. Rename variables: right-click → Rename
8. Key shortcuts: G=goto address, Space=toggle asm/listing, L=label
```

### Common CTF Binary Patterns
```bash
# 1. Hardcoded XOR key
# Look in decompiler for: loop + XOR operator
# Key insight: encrypted_flag[i] ^ key[i % keylen] = flag[i]
python3 -c "
enc = bytes([0x41, 0x42, 0x43])  # from binary
key = bytes([0x01, 0x02, 0x03])  # found in binary
print(bytes(a^b for a,b in zip(enc,key)).decode())"

# 2. strcmp with flag (visible in ltrace)
ltrace ./binary <<< "CTF{test}"  # try flag format

# 3. Custom base encoding
# Identify alphabet string in binary (e.g., "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
# Trace through decode loop

# 4. Anti-debug tricks
# ptrace call → returns -1 if debugger attached → patch: nop the check or set return 0
# time() check → patch out
```

### Pwntools Template
```python
from pwn import *
context.arch = 'amd64'
context.log_level = 'debug'  # remove for less noise

p = process('./binary')
# p = remote('TARGET', PORT)

# Basic interaction
p.sendline(b'input')
print(p.recvline())
print(p.recvall())

# Buffer overflow
payload = cyclic(100)         # find offset
p.sendline(payload)
p.wait()
core = p.corefile
offset = cyclic_find(core.read(core.rsp, 4))
print(f"Offset: {offset}")

# ROP chain
rop = ROP('./binary')
rop.raw(offset * b'A')
rop.call('system', [next(p.search(b'/bin/sh'))])
p.sendline(rop.chain())
p.interactive()
```

---

## 4. Crypto CTF

### RSA Attacks
```python
# Small public exponent (e=3, small ciphertext)
import gmpy2
c = int("0x...", 16)
n = int("0x...", 16)
m, exact = gmpy2.iroot(c, 3)
if exact:
    print(bytes.fromhex(hex(m)[2:]).decode())

# Common modulus attack (same n, two different e values, same message)
# Extended Euclidean: s1*e1 + s2*e2 = 1
# m = (c1^s1 * c2^s2) % n
import sympy
s1, s2 = sympy.gcdex(e1, e2)[0:2]
m = pow(c1, s1, n) * pow(c2, s2, n) % n

# Factorize small n
from Crypto.PublicKey import RSA
# If n < 512 bits: try factordb.com or sympy.factorint(n)
import sympy
p, q = sympy.factorint(n).keys()
phi = (p-1)*(q-1)
d = pow(e, -1, phi)    # Python 3.8+
print(bytes.fromhex(hex(pow(c, d, n))[2:]))
```

### Hash Length Extension
```bash
# Tool: hashpump
hashpump -s "KNOWN_HASH" -d "original_data" -a "&admin=true" -k KEY_LENGTH
# Works on: MD5, SHA1, SHA256, SHA512
# Use when: MAC = hash(secret + message) and you control message + know hash
```

### CBC Bit Flip Attack
```python
# Flip bit in ciphertext block N-1 to change plaintext in block N
# Effect: CT[i-16] ^= original_byte ^ target_byte
ct = bytearray(ciphertext)
ct[target_position - 16] ^= ord(original_char) ^ ord(desired_char)
# Submit modified ciphertext
```

### Padding Oracle
```bash
# Tool: padbuster
padbuster http://TARGET/page CIPHERTEXT_BASE64 BLOCK_SIZE -encoding 0

# Or: python-paddingoracle library
# Attack: systematically find padding-valid bytes → decrypt block by block
```

### ECB Mode Detection / Attack
```python
# Detect: encrypt 48 identical bytes → if two consecutive blocks identical = ECB
payload = b'A' * 48
ct = encrypt(payload)
blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
if blocks[0] == blocks[1]:
    print("ECB mode detected")

# ECB cut-and-paste: rearrange blocks to forge admin token
# If format: email=USER@x.com&uid=10&role=user
# Craft email so 'admin' lands on block boundary, swap blocks
```

### XOR Key Recovery
```python
# If key shorter than plaintext (repeating XOR):
# XOR two ciphertexts encrypted with same key:
# CT1 ^ CT2 = PT1 ^ PT2  (key cancels out)
# Many-time pad: use dcode.fr/xor-cipher or xortool

# If you know part of plaintext:
# key = known_pt ^ ct_at_same_position

import os
ct = bytes.fromhex("DEADBEEF...")
known_pt = b"flag{" 
key_fragment = bytes(a^b for a,b in zip(ct, known_pt))
```

---

## 5. OSINT (CTF)

### Reverse Image Search
```bash
exiftool image.jpg          # GPS coords, device, author
# Google Lens / TinEye / Yandex reverse image
# Google Maps: paste GPS coords to identify location
```

### Username / Profile OSINT
```bash
# sherlock — find username across social networks
sherlock USERNAME

# maigret — extended (500+ sites)
maigret USERNAME
```

### Domain / Email OSINT
```bash
whois domain.com
theHarvester -d domain.com -b google,linkedin,twitter
# Hunter.io, RocketReach for email format
# OSINT Framework: osintframework.com
```

---

## 6. Misc CTF Tricks

### Magic Bytes (File Type Spoofing)
```bash
# Restore correct header if file is disguised
# PNG: 89 50 4E 47 0D 0A 1A 0A
# JPEG: FF D8 FF
# ZIP: 50 4B 03 04
# PDF: 25 50 44 46 2D
# Fix: printf '\x89\x50\x4E\x47' | dd bs=1 of=file conv=notrunc
```

### QR Code Recovery
```bash
# If damaged/distorted QR code
# zbarimg challenge.png       # decode
# QR code repair tools: QRazyBox (online), quirc
zbarimg challenge.png
```

### Whitespace / Invisible Characters
```bash
# Snow steganography (whitespace in text files)
snow -C file.txt

# Unicode hidden chars
cat -A file.txt              # shows control chars
python3 -c "print([hex(ord(c)) for c in open('file.txt').read()])"
# Look for zero-width joiner (U+200D), soft hyphen, etc.
```

### Password Hash Quick Reference (CTF)
```
$1$   → MD5crypt    → hashcat -m 500
$2y$  → bcrypt      → hashcat -m 3200
$5$   → SHA-256crypt → hashcat -m 7400
$6$   → SHA-512crypt → hashcat -m 1800
$P$   → phpass      → hashcat -m 400
Plain MD5: 32 hex   → hashcat -m 0
NTLM: 32 hex        → hashcat -m 1000
SHA1: 40 hex        → hashcat -m 100
```
