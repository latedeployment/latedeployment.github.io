---
title: "Certificate Transparency as Communication Channel"
date: 2026-01-25T10:00:00
tags: ["security", "certificate transparency"]
ShowToc: true
TocOpen: true
---

_This is part three of the Certificate Transparency series_.

# Introduction

Described here is a way to leverage the infrastructure used to validate certificates in order to distribute messages through the Certificate Transparency Logs. 

The reader never connects back to the sender domain and the data is also never _deleted_.

# TL;DR Walkthrough

- Buy a domain, say `example.com`
- Cheap VPS with DNS of your domain pointed to the server
- Generate certificate with hidden data
- Use `Let's Encrypt` to sign the certificate, the data will be stored in certificate transparency logs
- Reader looks up for certificates of the known domain and reads the messages
- Reader only communicates with domains of the certificate transparency logs api endpoint

# Background

See part one [Certificate Transparency 101](/posts/certificate-transparency-101/) for more information about Certificate Transparency.

Certificate Transparency Logs are publicly accessible, append-only
Merkle hash trees of certificates issued by certificate authorities.

They behave similarly to a blockchain, so the data can never be deleted
from them.

The logs can be used for:

- **Detecting misuse of certificates**
- **Providing accountability** (tracking who issued which certificate)
- **Allowing browsers to verify** that certificates are logged before trusting the domains you visit

Each Certificate Authority has its own log and tools like `crt.sh`
allow searching on those logs, but you can easily communicate with the
API on your own. The API for the logs is described in _RFC 6962_ and
each CA has its own API endpoint to allow queries.

We therefore have some sort of a log we can append data to, given we
have a domain we own and can create certificates for it.

If the reader reads the certificate through the API,
it does not communicate with our domain at all, but instead reads the
data through the CA domain itself.

To make it even more interesting, we can embed some data inside the
certificate itself, by either leveraging X.509 extensions or some usage
of the Subject Alternative Name (SAN), but here I chose the Public Key
itself.


# Hiding Data

I assume the readers here know what RSA is, so I'd skip the math part.

Basically, if we search for prime numbers *long enough*, we can find
primes such that, when we multiply them together (forming the RSA
modulus),
specific values appear in certain bits of that modulus. In other words,
by carefully picking the primes, we can *embed our message* in the
modulus itself.

In this specific demonstration I used the lower bits of the modulus,
but we can actually do much more clever things like skipping bits, so
let's say every 10th bit is a hidden bit or something like that.
It's not very important.

The search here is pretty fast to be honest, faster than expected (less than a minute), and
I am sure better people can come up with better ideas on how to hide
actual data. In practice, the hidden data itself can be encrypted so it would look like
random ("regular") bits, the reader only has to know where to look.

After we created the primes, we can use them to generate a certificate
and append it to the certificate transparency logs.

I've used Let's Encrypt with OpenBSD `acme-client`, but I am sure this
can be done differently. Let's Encrypt challenged my domain with some
HTTP requests and eventually approved my certificate.

In other words, we "uploaded" our certificate to the Certificate
Transparency Logs by providing Let's Encrypt the certificate, it then
approved it and the certificate with our embedded data was stored in the
logs *forever*.

Browsing to `crt.sh` and searching for my domain showed the certificate
after a few minutes, but querying the API directly showed it much
faster.

Eventually our certificate looks like this:

    Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    ============================================
                    ============== UNIMPORTANT DATA ============
                    ============================================
                    5b:48:65:6c:6c:6f:00:00:00:00:00:00:00:00:00:
                    00:01

So the data below has `Hello` in ASCII _48:65:6c:6c:6f_.

The entire flow is described below in the Python code I've attached,
specifically take a look at `generate_rsa_key_with_hidden_data`
function.


# Reading Through crt.sh

To make this example simpler, I'd use `crt.sh` directly. The `crt.sh`
website parses all relevant certificate transparency logs and provides an easier "API" to obtain
info about them, though it neither has a real API nor does it always
work (sometimes you have to refresh the pages as its DB was down).

```bash
$ domain="example.com"
$ cert_id=$(curl -s  "https://crt.sh/?q=${domain}&output=json" | jq -r '.[0].id')
$ cert=$(curl -s "https://crt.sh/?d=${cert_id}")
$ modulus=$(echo "$cert" | openssl x509 -noout -modulus | sed 's/Modulus=//')
$ message=$(echo "$modulus" | tr -d ':' | tail -c 33)
$ echo "$modulus"
$ echo "$message"
```
And we can read back our message hidden inside the certificate.


# Reading Through Certificate Transparency API

_RFC 6962 (Certificate Transparency)_ provides an API which allows us to
query the logs efficiently. If we want to find a specific certificate,
we can use binary search to home in on the entry by timestamp (say,
issuance date). These logs can be massive—some with over 1 billion
entries, so we have to use binary search.

But that means, in the worst case, we only need about 30 API queries to
find ANY certificate.

We first call the `get-sth` API to obtain the size of the tree (i.e.
how many entries there are in the logs), then we use `get-entries` with
`start` and `end` in a reasonable size to grab the certificates. Let's
say we know that a certificate was created on a specific date, we can
check if those certificates are close to ours and jump elsewhere until
we find the correct certificate.

Companies which provide Certificate Transparency Log endpoints are
Sectigo, DigiCert, Let's Encrypt, Cloudflare, Google and more. [3]

Once we read from the log we have to parse it to be able to read the
data which is defined here as an example:
```python
    # Decode the leaf input (MerkleTreeLeaf structure from RFC 6962)
    leaf_input = base64.b64decode(entry["leaf_input"])

    # MerkleTreeLeaf structure:
    # - Byte 0: Version (0x00)
    # - Byte 1: MerkleLeafType (0x00 for timestamped_entry)
    # - Bytes 2-9: Timestamp (8 bytes, milliseconds since Unix epoch)
    # - Bytes 10-11: LogEntryType (0x0000 for x509_entry,
    #                               0x0001 for precert_entry)

    timestamp_ms = int.from_bytes(leaf_input[2:10], byteorder='big')
    timestamp = datetime.fromtimestamp(timestamp_ms / 1000.0)

    # Get entry type to determine how to parse
    entry_type = int.from_bytes(leaf_input[10:12], byteorder='big')

    # Decode extra_data
    extra_data = base64.b64decode(entry["extra_data"])
    cert_data = None

    if entry_type == 0:  # x509_entry
        # For x509_entry: leaf_input has the certificate after header
        # Bytes 12-14: certificate length (3 bytes)
        # Bytes 15+: certificate DER
        cert_len = int.from_bytes(leaf_input[12:15], byteorder='big')
        cert_data = leaf_input[15:15 + cert_len]

    elif entry_type == 1:  # precert_entry
        # For precert_entry:
        # - leaf_input: header + issuer_key_hash(32) + tbs_cert
        # - extra_data: pre_certificate + chain
        #
        # extra_data format:
        # - 3 bytes: length of pre_certificate
        # - N bytes: pre_certificate (full DER cert with poison ext)
        # - 3 bytes: length of chain
        # - M bytes: chain
        cert_len = int.from_bytes(extra_data[0:3], byteorder='big')
        cert_data = extra_data[3:3 + cert_len]
    else:
        raise ValueError(f"Unknown entry type: {entry_type}")

    # Parse the certificate
    cert = x509.load_der_x509_certificate(cert_data, default_backend())

```

# Usage examples

The fact that the connections to read the data are to 'good' domains
(like Cloudflare or Sectigo) makes it much harder to stop the process
from reading the data. The data we store is also never deleted.

While Let's Encrypt does provide a rate limit on certificate issuance,
I am sure people will find ways to overcome this.

To build a big message, you only have to create multiple certificates,
stack them up and they would be logged, allowing us to expand the
limits of public key moduli.
Another approach is to create subdomains which can provide "storage"
for extra certificates to be used.


# Code

## Certificate Generation
```Python
#!/usr/bin/env python3
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers, RSAPublicNumbers
)

def miller_rabin(n, k=10):
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bit_size):
    """Generate a random prime of given bit size."""
    while True:
        candidate = secrets.randbits(bit_size - 1)
        candidate |= (1 << (bit_size - 1)) | 1  # Set MSB and LSB
        if miller_rabin(candidate, 20):
            return candidate

def generate_rsa_key_with_hidden_data(message, key_size=2048,
                                        data_bits=128):
    """
    Generate RSA key with hidden data in the modulus.

    The trick: we want (p * q) mod 2^data_bits = target
    So we pick q, then find p where:
        p mod 2^data_bits = target * q^(-1) mod 2^data_bits
    """
    prime_bits = key_size // 2
    data_bytes = (data_bits + 7) // 8

    # Pad message and convert to int
    msg_padded = message.ljust(data_bytes, b'\x00')
    target = int.from_bytes(msg_padded, 'big') | 1  # Must be odd

    mask = (1 << data_bits) - 1

    # Generate fixed prime q
    q = generate_prime(prime_bits)

    # Calculate required lower bits for p
    q_inv_mod = pow(q, -1, 1 << data_bits)
    p_lower = (target * q_inv_mod) & mask

    # Find prime p with those lower bits
    upper_bits = prime_bits - data_bits
    for _ in range(100000):
        upper = secrets.randbits(upper_bits - 1)
        upper |= (1 << (upper_bits - 1))
        p_candidate = (upper << data_bits) | p_lower


        if p_candidate.bit_length() != prime_bits:
            continue
        if miller_rabin(p_candidate, 20):
            p = p_candidate
            break
    else:
        raise ValueError("Could not find suitable prime")

    if p < q:
        p, q = q, p

    n = p * q
    e = 65537
    phi_n = (p - 1) * (q - 1)
    d = pow(e, -1, phi_n)
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = pow(q, -1, p)

    pub = RSAPublicNumbers(e, n)
    priv = RSAPrivateNumbers(p, q, d, dp, dq, qinv, pub)
    return priv.private_key(default_backend())

def extract_from_modulus(n, data_bits=128):
    """Extract hidden data from modulus. No private key needed"""
    mask = (1 << data_bits) - 1
    data_int = n & mask
    return data_int.to_bytes((data_bits + 7) // 8, 'big')

def create_certificate(private_key, domain):
    """Create a self-signed certificate."""
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]),
            critical=False
        )
        .sign(private_key, hashes.SHA256())
    )
    return cert

# === Main ===
message = b"Hello"
domain = "example.com"

# Generate key with hidden data
private_key = generate_rsa_key_with_hidden_data(message)

# Create certificate
cert = create_certificate(private_key, domain)

# Save certificate
with open("cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

# Verify: extract hidden data from public key
n = private_key.public_key().public_numbers().n
extracted = extract_from_modulus(n)
print(f"Hidden message: {extracted}")  # b'Hello\x00...\x01'
```

## Deployment 

The following shows how to deploy the certificate to an OpenBSD
server and run acme-client to obtain a Let's Encrypt certificate.

### Generate the key locally with hidden data

```bash
# we call the tool from above
$ python cert_generator.py -d example.com -m "secret" -t pubkey

# This creates:
#    - output/example_com.key  (private key with hidden data in modulus)
```

### Deploy key to OpenBSD server
```bash
$ DOMAIN="example.com"
$ SERVER="user@myserver.example.com"

# Copy the key with hidden data
$ scp output/example_com.key \
    ${SERVER}:/etc/ssl/private/${DOMAIN}.key
$ ssh ${SERVER} "chmod 600 /etc/ssl/private/${DOMAIN}.key"
```

### Configure acme-client on the server

    # SSH into the server and create /etc/acme-client.conf:

    authority letsencrypt {
        api url "https://acme-v02.api.letsencrypt.org/directory"
        account key "/etc/acme/letsencrypt-privkey.pem"
    }

    domain example.com {
        domain key "/etc/ssl/private/example.com.key"
        domain certificate "/etc/ssl/example.com.crt"
        domain full chain certificate "/etc/ssl/example.com.pem"
        sign with letsencrypt
    }

### Run acme-client to obtain certificate
```bash
$ ssh ${SERVER} "acme-client -v ${DOMAIN}"
```

### Fetch and verify the certificate
```bash
$ scp ${SERVER}:/etc/ssl/${DOMAIN}.crt ./output/
$ openssl x509 -in output/${DOMAIN}.crt -noout -modulus
```

We're done and uploaded our data to the Certificate Transparency Logs.


# References

[1] RFC 6962 - Certificate Transparency

[2] crt.sh - Certificate Search

[3] https://certificate.transparency.dev/logs/