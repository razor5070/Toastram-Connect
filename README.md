# ToastRAM Connect SDK

Cross-platform native connection SDK for the ToastRAM memory service.

**Status: early foundation, not yet a usable pairing client.** This repository
will own the portable `.toastlink` importer, cryptographic integrity checks,
mutually agreed secure enrollment protocol, and portable client-connection API.
ToastRAM remains the server; client wrappers will call the native library.

## Project boundaries

- **Rust core:** bounded file import, canonical HTTPS server origin, X.509 CA
  certificate structure and signing-purpose checks, SHA-256 fingerprinting,
  and, later, verified HTTPS enrollment and credential handoff.
- **C ABI:** stable opaque handles and minimal metadata introspection so C/C++,
  C#, Swift, Kotlin, Python, and other languages can build thin wrappers.
- **Security rule:** hashing a file does **not** authenticate a server or its
  issuer. Initial server identity requires an independent trust check. Never
  disable TLS validation or enroll based solely on a digest.
- **Secret rule:** connection files contain temporary enrollment secrets and
  are sensitive until redeemed/expired. Never log tokens or embed the CA
  *private* key.
- **Rollout rule:** no actual server enrollment route is implemented in this
  first milestone. The Rust library must not pretend a parsed file is verified.

The first import schema is a **draft**, subject to coordinated changes before
a public SDK release. See [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Development

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Integration goals

Windows, macOS, Linux, iOS, and Android will share the same core. Operating-
system-specific credential stores and platform binaries will be implemented
as adapters, not separate protocol implementations.

License is pending owner selection.

### Windows C++ import

Build the DLL with `cargo build --locked -p toastlink-ffi`. Include
`include/toastlink.hpp`, link the matching `toastlink_ffi.dll.lib`, and
place `toastlink_ffi.dll` beside the executable. Pass at most 64 KiB to
`toastlink::import_file`. Its owning handle releases the import automatically.
`toastlink::metadata` returns public JSON for preview. A successful import
has status `unverified`.

Verified on Windows x64 with the Rust workspace tests and a C++17 client
linked against the Debug DLL. The client exercised successful import, metadata
retrieval and preservation of its original handle after a failed replacement.

At server revision 54a1d65 the provisioner creates HTTPS configuration and
an administrator bearer token. The next shared milestone requires issuer
records, an independently authenticated server identity, atomic single-use
enrollment, and server-enforced scoped credential revocation. Desktop
credential storage and authenticated memory readiness tests follow enrollment.

The authoritative frozen enrollment wire contract is [Enrollment API v1](docs/ENROLLMENT-API-v1.md).

### Enrollment v1 client test

Build the Windows helper with `cargo build --locked --bin toastlink`.
Run `toastlink preflight FILE.toastlink OPERATOR.json` to check eligibility.
Run `toastlink pair FILE.toastlink OPERATOR.json` for interactive redemption.
The operator record must come from a trusted channel independent of the file.
The CLI displays the credential locator after storage. Windows desktop hosts
can launch the same executable with `pair-dialog` for a native consent dialog.
Exit codes are 0 for success, 2 for declined consent, 3 for uncertain
redemption (reconcile with issuer), and 1 for other failures.
Preflight success is not a memory session readiness check.

The Windows disposable TLS smoke test uses Python with cryptography installed:
`python tests/disposable_tls.py target/debug/toastlink.exe`.
It uses a temporary loopback TLS server and removes its disposable Windows
credential. Real server replay, revocation and rollback behavior require
joint integration testing. Successful enrollment records the public origin, CA and vault locator atomically
in the current user's local application data under ToastRAM Connect/sessions.
The token stays in Windows Credential Manager. For credentials issued before
descriptor support, run `toastlink resume FILE.toastlink OPERATOR.json CLIENT_UUID`.
This command checks the existing credential binding offline and does not redeem the file.
C++ clients using cpp-httplib with OpenSSL can open the binding from
include/toastlink_win_http.hpp and apply it to same-origin requests. The server
enforces the credential's current scopes, expiry and revocation.

### Memory provenance response compatibility

`toastlink_win_http::Binding::Apply` configures authenticated HTTPS
requests (CA trust, origin checks and bearer credentials) using cpp-httplib;
it does **not** parse, filter, reconstruct, or serialize the JSON response.
Consequently, the optional `retrieved_memories` array added to ToastRAM
`POST /v1/auth/prepare` is preserved in the response body that the host
application receives. The existing `messages`, `persona_id`, and
`memory_count` fields remain unchanged.

The Sona integration is responsible for parsing the optional field and must
display it only when the corresponding injected memory block remains in the
final model prompt after context budgeting. This SDK does not make claims
about memory usage or source verification.

### SDK protocol hardening (development)

Restore responses require an explicit `memory_id` member: a UUID indicates
a restored memory and JSON `null` means the queue is empty. Missing keys
or malformed UUIDs are protocol errors and must **not** be interpreted as
a successful empty restore.

The typed `Prepared` response now preserves the optional
`retrieved_memories` array across the account FFI JSON boundary, including
its exact row order and metadata (`id`, `created_at`, `retrieval_score`,
`retrieval_method`, and optional `origin_kind`/`origin_ref`).
An older server's omitted field remains omitted; an explicit empty array
remains an empty array. No memory bodies are duplicated into provenance.
The client is responsible for dropping provenance if context budgeting
drops the corresponding injected memory block.

### Restore the last non-relevant memory

The existing account FFI entry point `toast_account_v2_call` accepts:

```json
{"op":"restore_last_memory","persona_id":"00000000-0000-4000-8000-000000000001"}
```

The SDK uses the authenticated account session to POST
`/v1/auth/memories/restore-last` to the verified ToastRAM origin.
It returns result JSON as `{"memory_id":"<uuid>"}` or
`{"memory_id":null}` if there is nothing to restore.
Only a `MEM_NON` record from that account/persona is eligible;
`MEM_STALE` remains excluded.
This is the operation used by Sona's `/memrestore` command.
Deploy the updated server before using the new SDK command.

### Desktop trust preview

Run `toastlink inspect FILE` for an offline public identity preview. Compare the
canonical origin, server ID and `ca_der_sha256` with the independent operator
console. `file_sha256` identifies this individual enrollment file. Inspecting
a file does not establish trust or contact its server. A desktop may pass a
previously verified public tuple directly as a single JSON argument after
`--verified-tuple` to the existing preflight or pair-dialog commands. The
SDK validates that tuple against the current file before sending credentials.
A changed prior Windows binding blocks enrollment.


## Published persona visual retrieval (account ABI v2)

Read-only operations use the already authenticated, issuer-bound device
session with persona scope; no credentials or arbitrary URLs are passed to
the host. They never call legacy bearer-fingerprint endpoints.

```json
{"op":"visuals","persona_id":"00000000-0000-4000-8000-000000000001"}
```

Returns the visual metadata object directly (revision, avatar, sprites,
manifest, optional studio_review). A missing avatar is explicit null.
Use the selected persona UUID, not a display name. Cache only verified
assets scoped to the authenticated issuer, account and persona.

```json
{"op":"visual_asset","persona_id":"00000000-0000-4000-8000-000000000001","kind":"sprites","sha256":"<64 lowercase hex from metadata>","mime":"image/png"}
```

Returns sha256, mime, data_base64. Only avatar/sprites kinds are permitted.
The SDK checks exact MIME, ETag, SHA-256, image signature and the existing
2 MiB binary limit. The JSON result fits the desktop's 4 MiB FFI copy cap.
A changed hash is a protocol failure: refresh metadata, never display
mismatched bytes. The desktop must additionally decode pixels, validate
frame bounds, reject stale persona/connection generations, and atomically
swap matching visual sets. No visual writes or publication are exposed here.

The Rust validation workflow runs on development as well as main. Its
Windows job builds the locked dependency graph, runs the disposable TLS
tests, and retains the DLL, MSVC import library, CLI and account ABI header
as a commit-specific artifact only after successful validation. It does
not deploy, publish a release, or modify any live account.
