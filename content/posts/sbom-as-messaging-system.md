---
title: "SBOM as Messaging System"
date: 2026-01-28T12:27:51+02:00
tags: ["security", "certificate transparency", "SBOM", "sigstore", "rekor"]
ShowToc: true
TocOpen: true
---

_This is part four of the Certificate Transparency series_.

See also previous parts:

- [Part 1: Certificate Transparency 101](/posts/certificate-transparency-101/)
- [Part 2: Certificate Transparency Info Leaks](/posts/certificate-transparency-info-leaks/)
- [Part 3: Certificate Transparency as Communication Channel](/posts/certificate-transparency-as-communication-channel/)


# Introduction

Described here is a way to leverage the infrastructure used to store SBOM (`Software Bill of Materials`) certificates in order to distribute messages via the sigstore database.

# TL;DR Walkthrough

- Sender generates a passphrase: `4-karma-eagle-kettle-horizon`
- Data is encrypted using a key derived from the passphrase
- Encrypted data is chunked and hidden in RSA public key moduli
- Each chunk is uploaded to `rekor` as a signed entry
- Receiver enters the same passphrase, searches `rekor`, extracts and decrypts
- **No direct connection between sender and receiver is ever established**

# Background

As described in [Part 3: Certificate Transparency as Communication Channel](/posts/certificate-transparency-as-communication-channel/), it's possible to "hide" small chunks of data inside the certificate public key. 

We use `rekor` with chunks as our DB to distribute messages, the reader reads through `sigstore` API, so no direct communication between the two parties.

## Sigstore and Rekor

[Sigstore](https://www.sigstore.dev/) is an open-source project used to improve supply chain security, making it easy to sign, verify, and authenticate software artifacts. It allows anyone to sign build artificats or container images and allow others to verify that signature.

Sigstore uses [Rekor](https://github.com/sigstore/rekor) as its transparency log implementation. Rekor acts similarly to regular Certificate Transparency logs, except that it is used for software supply chain metadata (signatures, SBOMs, attestations, etc.). Whenever a signature or metadata is produced with [Cosign](https://github.com/sigstore/cosign) an entry is generated. This is similar to `Let's Encrypt` issuance of certificates, only here the caller itself provides the data.

## The Magic-Wormhole Pattern

[magic-wormhole](https://github.com/magic-wormhole/magic-wormhole) is a tool for sending files securely from one computer to another. Both sender and receiver use a one-time code (like `7-horse-battery`) to connect. Once both enter the code, the wormhole links the computers directly or via a relay, and files transfer end-to-end encrypted.

What we do here is merge our public key manipulation technique with the magic-wormhole idea of one-time codes to create a messaging system built on top of the `rekor` transparency log.

## Rekor Entry Structure

Rekor entries called `hashedrekord`, and their schema is defined [here](https://github.com/sigstore/rekor/blob/main/pkg/types/hashedrekord/v0.0.1/hashedrekord_v0_0_1_schema.json).

The entry contains:
- An **artifact hash** (what was signed)
- A **signature** over that hash
- The **public key** used for signing

Notice that the public key is right there in the entry, and we already know from [Part 3](/posts/certificate-transparency-as-communication-channel/) that we can hide data in RSA public key moduli...

## Hiding Data in the Public Key

We use the exact same public key manipulation technique described in [Part 3](/posts/certificate-transparency-as-communication-channel/). The idea is simple: an RSA public key contains a modulus `n = p * q` where `p` and `q` are large primes. We can craft a key where one of the primes encodes our hidden data:

1. **Embed data in prime**: Generate a prime `p` where the lower bits contain our chunk data
2. **Generate matching prime**: Find another prime `q` such that `n = p * q` forms a valid RSA modulus
3. **Extract on receive**: Parse the public key, get the modulus `n`, and read the hidden bits directly

Since `rekor` stores the a full public key in each entry, the receiver can extract the modulus and retrieve the hidden chunk without needing the private key.

> **Deep Dive**: For a detailed explanation of how this technique works, including the math, code, and step-by-step walkthrough, see [How to Hide Encrypted Data Inside RSA Public Keys](/posts/hiding-data-in-rsa-public-keys/).

# "Architecture"

The system works like this:

1. **Sender** generates a passphrase
2. From the passphrase, both encryption key AND artifact hashes are derived
3. Data is encrypted, chunked, and uploaded as multiple `rekor` entries
4. **Receiver** enters passphrase, searches by derived hashes, and decrypts

Note that the **artifact hash serves as the rendezvous point**. Both sender and receiver independently compute the same hash from the passphrase, allowing the receiver to find entries in `rekor` without knowing anything except the passphrase.

# How It Works

## The Passphrase

It can be anything. I selected the `magic-wormhole` passphrases word list generation like `X-wordA-wordB-wordC-wordD`, but this can be anything else we'd want. 

## Deriving Keys and Hashes

From the passphrase we derive two critical pieces, the encryption key (let's assume it's PBKDF2), and artifact hashes.

## Sending Data

We basically encrypt the data, chunk it to by its size and upload it to `rekor` with hashes, something like hashing as `passphrase:chunk:N`, but in fact that it can be a any different method you can think of. 

It would look something like that:

![Sender Flow](/images/rekor-sender-flow.svg)

## Receiving Data

The receiver uses the passphrase to compute the hashes as well, and it then:

1. **Search**: For sequence 0, 1, 2, ..., compute artifact hash and search `rekor`
2. **Extract**: From each entry, get the RSA public key and extract hidden data from modulus
3. **Concatenate**: Sort chunks by sequence and concatenate them together
4. **Decrypt**: Decrypt with the derived key

![Receiver Flow](/images/rekor-receiver-flow.svg)

## Chunk Format

Each chunk stores 15 bytes, but RSA requires odd moduli (LSB must be 1). To avoid corruption, we shift the data left by 8 bits:

![Chunk Format](/images/rekor-chunk-format.svg)

# Rekor API

The implementation only needs three `rekor` API calls:

## Upload Entry

Upload a `hashedrekord` entry containing our crafted public key:

```bash
curl -X POST "https://rekor.sigstore.dev/api/v1/log/entries" \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "0.0.1",
    "kind": "hashedrekord",
    "spec": {
      "data": {
        "hash": {
          "algorithm": "sha256",
          "value": "abc123...derived-from-passphrase..."
        }
      },
      "signature": {
        "content": "BASE64_SIGNATURE",
        "publicKey": {
          "content": "BASE64_PUBLIC_KEY_WITH_HIDDEN_DATA"
        }
      }
    }
  }'
```

Response contains the entry UUID:

```json
{
  "24296fb24b8ad77a...": {
    "logIndex": 123456789,
    "body": "..."
  }
}
```

## Search by Hash

Find entries by artifact hash (the rendezvous point):

```bash
curl -X POST "https://rekor.sigstore.dev/api/v1/index/retrieve" \
  -H "Content-Type: application/json" \
  -d '{"hash": "sha256:abc123...derived-from-passphrase..."}'
```

Returns list of matching UUIDs:

```json
["24296fb24b8ad77a..."]
```

## Get Entry

Fetch full entry to extract the public key:

```bash
curl "https://rekor.sigstore.dev/api/v1/log/entries/24296fb24b8ad77a..."
```

Response body (base64 decoded) contains the public key with our hidden data:

```json
{
  "apiVersion": "0.0.1",
  "kind": "hashedrekord",
  "spec": {
    "signature": {
      "publicKey": {
        "content": "BASE64_PUBLIC_KEY"
      }
    }
  }
}
```

The receiver decodes the public key, extracts the RSA modulus, and retrieves the hidden chunk data.

# Summary

We have an ability to 'ride along' with `rekor` db with public key manipulation to
pass messages between two parties. Given that the API public, the reader and
sender both communicates through `sigstore` domain only. It takes roughly a
minute to compute and upload a small messgae like _"the dog barks too loud, can it be silenced?"_. 
Reading the message is fairly fast though.
