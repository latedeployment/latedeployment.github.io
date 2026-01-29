---
title: "Encrypting and Chunking Data in RSA Public Keys"
date: 2026-01-29T10:00:00+02:00
tags: ["security", "cryptography", "RSA", "steganography", "AES"]
ShowToc: true
TocOpen: true
---

_This is part two of the RSA Public Key Manipulation series_.

See also [Part 1: How to Hide Data Inside RSA Public Keys](/posts/hiding-data-in-rsa-public-keys/)

# Introduction

[Part 1](/posts/hiding-data-in-rsa-public-keys/) is showing how to embed data in the lower bits of an RSA public key modulus, but this is very lame because the "hidden" data is not encrypted and the size of the message is limited. As shown in [SBOM Messaging System](/posts/sbom-as-messaging-system/) to send arbitrary encrypted messages through Rekor, we use chunks and a passphrase to embed arbitrary length of a message in a list of RSA public keys, _encrypted_.

# Encryption Flow

![Encryption and Chunking Pipeline](/images/rsa-encryption-pipeline.svg)

# Step 1: Derive Encryption Key from Passphrase

We use a passphrase (like `4-karma-eagle-kettle`) as the shared secret. Both sender and receiver derive the same encryption key from it using PBKDF2.

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KDF_SALT = b"whatever-salt-we-want"
KDF_ITERATIONS = 100_000

def derive_key(passphrase: str) -> bytes:
    """Derive 256-bit AES key from passphrase."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=KDF_SALT,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(passphrase.encode('utf-8'))
```

# Step 2: Encrypt with AES-GCM

`AES-GCM` provides both encryption and integrity with authentication tag, but comes with the cost that the encrypted output is slightly larger than the input:


    encrypted = nonce (12 bytes) + ciphertext + tag (16 bytes)


```python
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt with AES-256-GCM. Returns nonce + ciphertext + tag."""
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)  # Random 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext  # Tag is appended by encrypt()


def decrypt(encrypted: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM. Input is nonce + ciphertext + tag."""
    aesgcm = AESGCM(key)
    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)
```

# Step 3: Length Header

Before chunking, we need to know the exact size of the encrypted data for reassembly. We add a 4-byte length header:

```python
def prepare_for_chunking(data: bytes) -> bytes:
    """Prepend 4-byte length header."""
    length = len(data)
    return length.to_bytes(4, 'big') + data
```

# Step 4: Chunks

We split the data into fixed size chunks that fit in RSA moduli. Each chunk needs:
- **Sequence number** (2 bytes) — for ordering
- **Total count** (2 bytes) — to know when we have all chunks
- **Payload** (11 bytes) — actual data

![Chunk Structure](/images/rsa-chunk-structure.svg)

```python
from dataclasses import dataclass
from typing import List

CHUNK_PAYLOAD_SIZE = 11  # Bytes of actual data per chunk
CHUNK_HEADER_SIZE = 4    # 2 bytes seq + 2 bytes total

@dataclass
class Chunk:
    sequence: int   # 0, 1, 2, ...
    total: int      # Total number of chunks
    payload: bytes  # 11 bytes of data


def chunk_data(data: bytes) -> List[Chunk]:
    """Split data into chunks."""
    total = (len(data) + CHUNK_PAYLOAD_SIZE - 1) // CHUNK_PAYLOAD_SIZE
    if total == 0:
        total = 1
    
    if total > 65535:
        raise ValueError(f"Data too large: {total} chunks needed (max 65535)")
    
    chunks = []
    for i in range(total):
        start = i * CHUNK_PAYLOAD_SIZE
        end = start + CHUNK_PAYLOAD_SIZE
        payload = data[start:end]
        
        # Pad last chunk with zeros
        if len(payload) < CHUNK_PAYLOAD_SIZE:
            payload = payload + b'\x00' * (CHUNK_PAYLOAD_SIZE - len(payload))
        
        chunks.append(Chunk(sequence=i, total=total, payload=payload))
    
    return chunks
```

We do have a **11 bytes payload limit**.

- RSA-2048 modulus: 2048 bits = 256 bytes
- We use lower 128 bits = 16 bytes
- Minus 1 byte for RSA LSB requirement = 15 usable bytes
- Minus 4 bytes header = 11 bytes payload

# Step 5: Encode for RSA Modulus

RSA moduli are always odd (LSB = 1), so we can't use the lowest bit for data. We shift our data left by 8 bits:

![RSA Encoding](/images/rsa-chunk-encoding.svg)

```python
def encode_for_rsa(chunk: Chunk) -> bytes:
    """
    Encode chunk to 16 bytes for RSA modulus embedding.
    
    Layout (before shift):
    [seq:2][total:2][payload:11] = 15 bytes
    
    After shift left 8 bits + set LSB:
    [seq:2][total:2][payload:11][0x01] = 16 bytes
    """
    header = chunk.sequence.to_bytes(2, 'big') + chunk.total.to_bytes(2, 'big')
    raw = header + chunk.payload  # 15 bytes
    
    # Shift left 8 bits and set LSB to 1
    value = int.from_bytes(raw, 'big')
    shifted = (value << 8) | 0x01
    
    return shifted.to_bytes(16, 'big')


def decode_from_rsa(data: bytes) -> Chunk:
    """Extract chunk from 16 bytes of RSA modulus."""
    value = int.from_bytes(data, 'big')
    
    # Shift right 8 bits to remove padding byte
    shifted = value >> 8
    raw = shifted.to_bytes(15, 'big')
    
    sequence = int.from_bytes(raw[:2], 'big')
    total = int.from_bytes(raw[2:4], 'big')
    payload = raw[4:]
    
    return Chunk(sequence=sequence, total=total, payload=payload)
```

# Step 6: Generate RSA Key with Embedded Chunk

For each chunk, we generate an RSA key where the modulus contains our encoded data. This is detailed in [Part 1](/posts/hiding-data-in-rsa-public-keys/).

# Receiving

```python
def reassemble(chunks: List[Chunk]) -> bytes:
    """Reassemble chunks into original data."""
    # Sort by sequence
    chunks.sort(key=lambda c: c.sequence)
    
    # Verify completeness
    total = chunks[0].total
    sequences = {c.sequence for c in chunks}
    missing = set(range(total)) - sequences
    if missing:
        raise ValueError(f"Missing chunks: {sorted(missing)}")
    
    # Concatenate payloads
    raw = b''.join(c.payload for c in chunks)
    
    # Extract length and trim padding
    length = int.from_bytes(raw[:4], 'big')
    encrypted = raw[4:4 + length]
    
    return encrypted
```

Then decrypt with the derived key:

```python
# Receiver has the passphrase
key = derive_key(passphrase)
encrypted = reassemble(chunks)
plaintext = decrypt(encrypted, key)
```

# Complete Example

```python
# === SENDER ===
passphrase = "4-karma-eagle-kettle"
message = b"Hello, World!"  # 13 bytes

# 1. Derive encryption key
key = derive_key(passphrase)
# key = bytes(32)

# 2. Encrypt
encrypted = encrypt(message, key)
# encrypted = 13 + 12 + 16 = 41 bytes

# 3. Prepend length
with_length = prepare_for_chunking(encrypted)
# with_length = 4 + 41 = 45 bytes

# 4. Chunk (45 bytes / 11 bytes per chunk = 5 chunks)
chunks = chunk_data(with_length)
# chunks = [Chunk(0, 5, b'...'), Chunk(1, 5, b'...'), ...]

# 5. For each chunk: encode and generate RSA key
for chunk in chunks:
    chunk_bytes = encode_for_rsa(chunk)  # 16 bytes
    private_key = generate_key_with_chunk(chunk_bytes)
    # Upload public key somewhere (CT logs, Rekor, etc.)
```

```python
# === RECEIVER ===
passphrase = "4-karma-eagle-kettle"

# 1. Derive same key
key = derive_key(passphrase)

# 2. Retrieve public keys and extract chunks
chunks = []
for public_key in retrieved_keys:
    n = public_key.public_numbers().n
    chunk_bytes = extract_from_modulus(n)  # Lower 128 bits
    chunk = decode_from_rsa(chunk_bytes)
    chunks.append(chunk)

# 3. Reassemble
encrypted = reassemble(chunks)

# 4. Decrypt
plaintext = decrypt(encrypted, key)
print(plaintext)  # b'Hello, World!'
```

# SecertCert

See [secertcert](https://github.com/latedeployment/secertcert) for full implementaion.
