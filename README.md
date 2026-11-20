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
