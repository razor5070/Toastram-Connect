# ToastRAM Connect SDK

Cross-platform native connection SDK for the ToastRAM memory service.

**Status: early foundation, not yet a usable pairing client.** This repository
will own the portable `.toastlink` importer, cryptographic integrity checks,
mutually agreed secure enrollment protocol, and portable client-connection API.
ToastRAM remains the server; client wrappers will call the native library.

## Project boundaries

- **Rust core:** bounded file import, strict format validation, SHA-256 fingerprinting,
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
