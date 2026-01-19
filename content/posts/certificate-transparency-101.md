---
title: "Certificate Transparency 101"
date: 2026-01-19
tags: ["security", "certificate transparency"]
ShowToc: true
TocOpen: true
---

_This is part one of the Certificate Transparency series_.

Certificate Transparency (CT) is a public, append-only logging system for TLS
certificates. It was created to make certificate issuance observable so that
mis-issuance can be detected quickly and independently. Instead of relying 
only on trust, CT lets anyone audit which certificates were issued
for a domain and when they appeared in a public log.

## The problem CT solves

Before CT, the certificate ecosystem had a fundamental trust problem: you had to
trust that Certificate Authorities (CAs) were doing the right thing, but there
was no easy way to verify it. If a CA issued a fraudulent certificate for instance
through compromise or an error the only way to discover it was usually
after the damage was done. 

See for example _DigiNotar_, _Comodo_, and _CCNIC_ incidents.

In all these cases, detection was slow, and pretty much relied on luck.

CT solves this by making certificate issuance public.
Every publicly-trusted certificate must be logged to public, auditable logs before
browsers will accept it. 

So with CT: 

- Domain owners can monitor logs for unexpected certificates.
- Researchers can analyze issuance patterns across the entire ecosystem.
- Mis-issuance becomes visible directly.

## What Certificate Transparency is

Certificate Transparency is a set of public logs that accept certificates
and return cryptographic proofs that the certificates were logged. 

These logs are:

- **Append-only**: once a certificate is logged, it should remain in the log
  forever. Entries cannot be modified or deleted.
- **Publicly auditable**: anyone can verify log consistency and inclusion proofs.
  No authentication is required to read log contents.
- **Operated by independent organizations** to reduce single points of failure.
  No single entity controls all logs.
- **Cryptographically verifiable**: proofs are based on Merkle trees, so
  clients can verify claims without trusting the log operator.

The system also involves a few key actors:

- **Certificate Authorities (CAs)** submit certificates (or precertificates) to CT
  logs as part of their issuance process.
- **Logs** return Signed Certificate Timestamps (SCTs) — a signed promise that
  the certificate will be included in the log.
- **Browsers** require SCTs for publicly trusted certificates and enforce CT policy.
- **Monitors** watch the logs for suspicious or unexpected issuance and alert
  domain owners.
- **Auditors** verify that logs are behaving correctly and not omitting entries.

## Understanding the Merkle tree

CT logs are built on Merkle trees, a data structure for cryptographic
hashes.


### What is a Merkle tree?

A Merkle tree is a binary tree where:

- Each leaf node contains the hash of a data item (in CT, a certificate).
- Each internal node contains the hash of its two children concatenated.
- The root hash represents a cryptographic commitment to all data in the tree.

{{< figure src="/images/merkle-tree.svg" alt="Merkle tree structure" >}}

This structure enables two critical operations:

**Inclusion proofs**: Given a certificate, prove it exists in the log without
downloading the entire log. You only need the hashes along the path from your
leaf to the root—O(log n) hashes for a tree with n entries.

For example, to prove Cert B is in the tree above, you only need:
1. H(A) — the sibling of H(B)
2. H(CD) — the sibling of H(AB)
3. The root hash

You can then verify: Root = H(H(H(A) || H(B)) || H(CD))

**Consistency proofs**: Prove that a newer version of the log is a valid
extension of an older version—that no entries were modified or removed.

### Tree head and signing

The log periodically publishes a Signed Tree Head (STH), which includes:

- The tree size (number of entries).
- A timestamp.
- The root hash.
- The log's cryptographic signature over these values.

## What gets logged

A typical X.509 certificate contains:

### Subject and issuer information

- **Subject Distinguished Name (DN)**: May include organization name, location,
  common name, etc.
- **Issuer DN**: Identifies the CA that issued the certificate.

### Domain names

- **Common Name (CN)**: The primary domain name .
- **Subject Alternative Names (SANs)**: The authoritative list of domain names
  and IP addresses the certificate is valid for.

Example SANs might include:
```
DNS:example.com
DNS:www.example.com
DNS:api.example.com
DNS:staging.internal.example.com
DNS:10-0-1-42.pods.cluster.local
```

### Validity period

- **Not Before**: When the certificate becomes valid.
- **Not After**: When the certificate expires.

### Public key

The certificate's public key is included.

### Extensions

Various X.509 extensions including:

- Key usage constraints.
- Basic constraints (is this a CA certificate?).
- Certificate policies.
- Authority Information Access (where to find the issuer's certificate and OCSP).

## Certificates vs. precertificates

CT logs accept two types of entries:

### Certificates

A standard X.509 certificate. Logging a certificate after issuance means the
certificate can be used immediately.

### Precertificates

A precertificate is a special certificate-like structure that:

- Contains all the same information as the final certificate.
- Includes a "poison" extension (OID 1.3.6.1.4.1.11129.2.4.3) that marks it as
  invalid for TLS.
- Is signed by either the issuing CA or a dedicated precertificate signing
  certificate.

The workflow with precertificates:

1. CA creates a precertificate with all final certificate details.
2. CA submits precertificate to CT logs.
3. Logs return SCTs.
4. CA creates the final certificate, embedding the SCTs.
5. CA issues the final certificate to the subscriber.

This allows SCTs to be embedded directly in the certificate, which is the
cleanest delivery mechanism.

The precertificate and final certificate will have identical information except:

- The poison extension is removed.
- The SCT list extension is added.
- The signature is different (covers the modified extensions).

When searching CT logs, you may find either or both versions of a certificate.

## Signed Certificate Timestamps (SCTs)

An SCT is the log's promise to include a certificate in the log. It contains:

- **Log ID**: SHA-256 hash of the log's public key.
- **Timestamp**: When the log received the submission.
- **Extensions**: Reserved for future use (currently empty).
- **Signature**: The log's signature over the above fields plus the certificate.


## CT log APIs

CT logs expose an HTTP API. RFC 9162 defines the v2 endpoints:

### Submission endpoint

**`POST /ct/v2/submit-entry`**

Submit a certificate or precertificate for logging. Returns an SCT.

```json
{
  "submission": "base64-encoded-cert-or-precert",
  "type": 1,
  "chain": ["base64-encoded-issuer", ...]
}
```

The `type` field indicates what's being submitted:
- `1` for certificates (`x509_entry_v2`)
- `2` for precertificates (`precert_entry_v2`)

### Query endpoints

**`GET /ct/v2/get-sth`**

Get the current Signed Tree Head.

Response:
```json
{
  "tree_size": 123456789,
  "timestamp": 1705123456789,
  "sha256_root_hash": "base64-encoded-hash",
  "tree_head_signature": "base64-encoded-signature"
}
```

**`GET /ct/v2/get-sth-consistency?first=X&second=Y`**

Get a consistency proof between two tree sizes.

**`GET /ct/v2/get-proof-by-hash?hash=X&tree_size=Y`**

Get an inclusion proof for a leaf hash.

**`GET /ct/v2/get-entries?start=X&end=Y`**

Retrieve log entries by index. This is how monitors download certificates.

**`GET /ct/v2/get-all-by-hash?hash=X&tree_size=Y`**

Get both inclusion and consistency proofs in a single request.

**`GET /ct/v2/get-roots`**

Get the list of acceptable root certificates for this log.

## crt.sh

[crt.sh](https://crt.sh) is a public website that aggregates data from CT logs
into a searchable database. You can look up certificates by domain name,
organization, or certificate hash. It's a convenient way to explore what's in
the logs without querying them directly.

## CT log operators

The CT ecosystem includes logs operated by multiple organizations:

| Operator | Notable Logs |
|----------|--------------|
| Google | Argon, Xenon, Icarus, Pilot, Rocketeer |
| Cloudflare | Nimbus |
| DigiCert | Yeti, Nessie |
| Let's Encrypt (ISRG) | Oak |
| Sectigo | Sabre, Mammoth |
| TrustAsia | Trust Asia Log |

## Timeline and history

- **2011**: DigiNotar indcident.
- **2013**: RFC 6962 published; Google launches pilot logs.
- **2015**: Chrome begins requiring CT for EV certificates.
- **2018**: Chrome requires CT for all new certificates (April 30).
- **2021**: RFC 9162 published.
- **Present**: CT is mandatory for all publicly-trusted certificates in major
  browsers.

## Further reading

- [RFC 6962: Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962)
- [RFC 9162: Certificate Transparency Version 2.0](https://datatracker.ietf.org/doc/html/rfc9162)
- [Chrome CT Policy](https://googlechrome.github.io/CertificateTransparency/ct_policy.html)
- [crt.sh](https://crt.sh/)
- [Certificate Transparency website](https://certificate.transparency.dev/)
