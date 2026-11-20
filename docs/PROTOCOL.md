# ToastRAM Connect draft enrollment protocol

**Draft status: not yet deployed, not an interoperability guarantee.**
Nothing in this file adds an endpoint to the ToastRAM server. The current SDK
implements only offline file parsing and SHA-256 computation. It does **not**
enroll a client or establish an authenticated session.

## Roles

- **ToastRAM issuer:** produces a short-lived, single-use connection file
  and separately records its exact SHA-256 fingerprint and enrollment ID.
- **ToastLink importer:** parses a bounded file and calculates the exact raw
  byte digest. This step alone makes **no assertion of authenticity**.
- **Trust ceremony:** before first enrollment, the user independently verifies
  the server identity (e.g. installer-provided fingerprint via another channel)
  or imports identity through an already trusted provisioning system.
- **Enrollment server:** verifies the independently authenticated TLS server
  identity, compares the enrolled issuance fingerprint, and atomically consumes
  the one-time token to issue a scoped client identity.

## Proposed one-file JSON envelope (draft v1)

```json
{
  "format": "toastram.connection",
  "version": 1,
  "server": {
    "id": "8f694b5238e9a11b86c4cb003b1b346a",
    "name": "Example ToastRAM",
    "url": "https://memory.example.lan:18443"
  },
  "tls": {
    "ca_certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  },
  "enrollment": {
    "id": "a2940e55-374b-4a4f-a5e4-b15e3c3a9ed8",
    "token": "TEMPORARY_SINGLE_USE_RANDOM_ENROLLMENT_TOKEN",
    "expires_at": "2099-01-01T00:00:00Z"
  }
}
```

The example certificate and token are placeholders and not valid credentials.

The draft importer requires canonical lowercase UUIDv4 enrollment IDs, 32
lowercase hexadecimal characters for the server ID, a valid HTTPS server URL,
a single parseable X.509 PEM CA certificate (with CA BasicConstraints and
certificate-signing KeyUsage when present), a URL-safe token of 32-256
characters, and a non-expired RFC3339 timestamp. The importer exposes the
canonical parsed HTTPS origin, never the original URL spelling. The C ABI
reports expired and unsupported files with distinct reason codes.
These checks do **not** verify certificate trust, issuer identity, or TLS. It rejects unknown fields and files over 64 KiB.

**The public server CA certificate is not a private key and must never include
one.** An attacker who replaces the file can substitute both the server URL
and CA; trusting that bundle without an independent identity check would make
the hash preflight meaningless.

## Draft handshake stages (not implemented)

1. **Import:** parse a local `.toastlink` and hash its *exact bytes*.
   Raw-byte hashing means whitespace changes also change the digest.
2. **Verify identity:** validate HTTPS with the expected hostname and the
   issuer CA, and independently confirm the expected server identity through
   a trusted channel. No 'accept all certificates' fallback.
3. **Preflight:** over verified TLS, send enrollment ID and raw-file SHA-256.
   The issuer compares its stored digest. Failure responses must be generic,
   rate-limited, and must not reveal whether IDs or digests exist.
4. **Enroll:** prove possession of a short-lived one-time secret over verified
   TLS. The server atomically marks the token consumed, issues an independently
   revocable, least-privilege client credential, and prevents replay. The
   request/response schema is deliberately **not frozen yet**.
5. **Handoff:** save the client credential through an OS-specific protected
   credential store; delete transient token material where possible; hand a
   *session handle* to the host assistant, not raw reusable secrets.
6. **Operate:** support credential rotation, explicit revocation, certificate
   replacement, and independent access permissions for each assistant.

## Important trust distinction

SHA-256 is a file integrity fingerprint, **not authentication**. An attacker
who substitutes a file and controls its claimed server can report a matching
digest. Do not add a unauthenticated hash endpoint and claim it prevents
server emulation. Authenticity requires a separately established trust anchor
and a fully validated TLS connection.

## First implementation milestone

The Rust crate supplies `ConnectionFile::from_bytes` and `from_path`,
bounded validation, redacted debugging, SHA-256 of raw input, and public
metadata. `toastlink_import_json` and `toastlink_metadata_json` expose
the same offline features through an opaque C ABI, without exporting the
enrollment secret. The private token is zeroized when its owner is dropped
as far as ordinary process memory permits. This is not a guarantee against
copies held by the OS, the caller, or JSON allocation internals.

An unverified parsed connection file is **never** reported as connected,
authenticated, or ready for memory operations.

## Future packaging

One native Rust implementation, per-target binaries for Windows, macOS,
Linux, iOS, and Android, a C ABI, and thin C++, .NET, Swift, Kotlin, Python
wrappers. Platform credential-store adapters and actual enrollment code
will be developed and tested alongside the corresponding ToastRAM server
endpoints. This repo deliberately contains no desktop-specific code.
