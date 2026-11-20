# ToastRAM Connect Enrollment API v1 — proposal 1

Status: proposed for joint review. Freeze requires agreement from both maintainers. This specifies client pairing only. Issuance and administrative revocation belong to the server. Memory Transport API 1.6 continues to govern memory operations.

## File and independent trust

Use the existing strict toastram.connection version 1 envelope in PROTOCOL.md, maximum 65,536 bytes. Hash the exact file bytes with SHA-256, including whitespace. The issuer generates a token from 32 random bytes encoded as unpadded base64url, stores the issuance record, and sets expiry to ten minutes after issuance. The importer retains its existing token syntax for parsing. The server clock determines eligibility at redemption.

Before *either* HTTP call the SDK requires a trusted provisioning record obtained independently of the file: canonical HTTPS origin (including non-default port), server.id, and lowercase SHA-256 hex of the DER bytes of the issuer CA certificate. Match all three. Verify TLS certificate chain, hostname/IP SAN, validity and server-auth usage against that CA for every connection. Disable redirects and TLS early data. A changed trust record requires independently authorized reprovisioning. An imported file alone has state unverified. A successful preflight conveys eligibility at that instant only.

## HTTP conventions

POST over verified HTTPS. Bodies are UTF-8 JSON objects. Send Content-Type: application/json and Accept: application/json. Responses including errors use Cache-Control: no-store. Maximum body size 16 KiB. Reject duplicate keys, unknown request fields, wrong types and malformed encodings. Clients ignore additional response fields, validate every required field, and reject unknown token types or scopes. The /v1/ path selects the major version. Breaking changes require a new path. No redirects or alternate-origin credential forwarding.

Both calls require Authorization: Bearer <enrollment.token>. Only enrollment endpoints accept this credential. Never place tokens in URLs, logs or diagnostics. An issued session bearer cannot enroll another client. The two request bodies are identical:

    {"server_id":"8f694b5238e9a11b86c4cb003b1b346a","enrollment_id":"a2940e55-374b-4a4f-a5e4-b15e3c3a9ed8","file_sha256":"<64 lowercase hexadecimal digits>"}

server_id and enrollment_id use the exact canonical formats accepted by the importer. Both endpoints verify the bearer, server ID, enrollment ID, exact issued digest, expiry, revocation and unconsumed state. Compare secret verifiers in constant time. The server binds scopes to the issuance record. The client cannot request additional privileges.

## POST /api/connect/v1/preflight

200 with exactly these required fields:

    {"status":"eligible","enrollment_id":"a2940e55-374b-4a4f-a5e4-b15e3c3a9ed8"}

The SDK verifies the echoed ID. Repeated preflights are safe. No credential is issued, reserved or consumed. After user consent and a successful preflight, the SDK may redeem. The server independently rechecks all conditions even when a preflight succeeded.

## POST /api/connect/v1/redeem

201 after durable commit:

    {"token_type":"Bearer","access_token":"<opaque unpadded base64url>","client_id":"<canonical lowercase UUIDv4>","server_id":"8f694b5238e9a11b86c4cb003b1b346a","scopes":["memory.session"],"expires_at":"2030-01-01T00:00:00Z"}

Generate the session token from at least 32 cryptographically random bytes (encoded length 43–256). expires_at is a future RFC3339 UTC instant; the issuer selects the session lifetime. v1 defines one fixed profile, scopes exactly ["memory.session"]. It permits the existing desktop model discovery, memory-enabled chat, access check, explicit save and acknowledgement routes under their existing transport contracts. It confers no administrative, issuance, cross-client or model-management rights. Each redeemed identity is independently revocable. The server must enforce scope, expiry and revocation on every new authenticated request.

Atomically consume the enrollment and create one scoped credential. A crash before commit leaves neither change. Exactly one concurrent redemption can succeed. Subsequent attempts produce the generic denial below. Persist only protected verifiers on the server. Never return the token a second time.

The SDK checks the echoed server ID and response fields, then stores the token in the platform credential store bound to origin, trusted identity and client ID. Only after successful storage may it publish a session handle. Application readiness still requires its normal authenticated service checks. On expiry or revocation, stop using the credential and require fresh pairing. No refresh endpoint in v1.

## Errors and recovery

Error JSON: {"error":"enrollment_denied"}. Codes: 400 invalid_request; 401 enrollment_denied (missing/wrong bearer, well-formed but mismatched IDs or digest, expired, revoked, unknown or already consumed); 413 body_too_large; 415 unsupported_media_type; 429 rate_limited; 503 temporarily_unavailable. Credential-dependent denials share status and body. Rate-limit independently of whether a supplied enrollment ID exists. A 429 includes integer Retry-After seconds. Unknown version route returns 404. Do not expose enrollment-record details in responses.

SDK sends at most one automatic preflight retry after a transient transport error or 503. Respect 429 and return the delay to the caller. Never automatically retry redemption. A lost or malformed success response, or failure to persist the returned token, leaves pairing incomplete. Surface "pairing outcome uncertain"; use the issuer's record of enrollment_id to identify and revoke any orphaned client, then issue a fresh file. Server retains that administrative mapping across process restarts. No session handle or success indicator on this path.

## Shared acceptance fixtures before freeze

Use disposable CA, TLS server and issuer records. For a valid baseline use tests/fixtures/ca.pem as the offline parsing fixture; generate separate disposable TLS credentials for network tests. Both maintainers should approve a byte-identical sample file, its independently computed digest and a trusted provisioning tuple before freezing the wire contract. Acceptance cases:

- Matching trust tuple, hostname, bytes and secret: repeated preflight 200; redeem 201; authenticated memory access succeeds.
- Replace the CA and recompute the file hash, change the host, or present an expired TLS cert: no enrollment HTTP request reaches the peer.
- Whitespace-only file edit with original issuer record: digest differs; 401. Expired, revoked and consumed enrollment records yield the same 401 body.
- Race two redemptions: one 201, one 401; exactly one durable client record.
- Lose the response after commit or fail local secret storage: no usable SDK session; revoke orphan by enrollment record and re-pair.
- Pair two clients, revoke one and restart server: that client receives 401 on its next memory request; the other still succeeds. Enrollment bearer fails on protected memory routes; session bearer fails on enrollment routes.
- Rate limit returns 429 with delay; credentials and request bodies absent from diagnostic logs.

Ownership: ToastRAM implements issuer, endpoints and credential enforcement. Connect implements import, trust, client handshake, protected credential storage and SDK fixtures. Validate together on disposable instances.
