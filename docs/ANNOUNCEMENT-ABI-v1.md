# Announcement ABI v1 (development)

Additive to the existing account ABI v2. No new DLL symbol or dependency.
The profile scope is sufficient. Fixed HTTPS paths, no redirects, no arbitrary
URLs, no new credentials, no model context or memory integration.

On a single background worker per session, poll approximately every 15 seconds
while connected; back off on errors and 429 (at least 60 seconds for 429).
A legacy server may return 404; disable polling until reconnect or upgrade.
No autonomous SDK thread is started. Calls remain blocking on that worker.
Poll/ACK release the account session lock during HTTPS I/O. Refresh can still
take the usual credential rotation lock. Discard results after host session
change; the SDK also rejects replaced access tokens and superseded poll results.

Operations via toast_account_v2_call:

- {"op":"announcement_poll"} -> {"available":[UUID...],"pending_ack":[UUID...]}
- {"op":"announcement_claim","id":"UUID"} -> null for duplicate or
  {"id":UUID,"body":text,"starts_at":RFC3339,"expires_at":RFC3339,"valid_for_ms":N}
- {"op":"announcement_ack","id":"UUID"} -> {"acknowledged":true}

Process pending_ack IDs on every poll; retry only when offered again. Claim
available IDs immediately before publishing a separate plain-text UI notice.
Check the same host session and monotonic time since the claim began against
valid_for_ms before presenting; never enqueue for display after expiry. If a
claim expires, poll again. ACK after successful UI acceptance, not after fetch.
A 409 ACK means the offer is no longer accepted; do not retry it outside a
fresh active offer. Malformed responses and storage errors fail closed.
Do not block generation or insert notice text in chat history, logs or prompts.
Do not run overlapping polls or start a new poll until its claims/ACKs finish.

The SDK uses a per-origin/trust/account/device directory in the OS user data
directory (ToastRAMConnect/announcement-receipts-v1). UUID-only empty markers
are created atomically before text is handed to the host. No notice body or
credential is saved there. Receipts survive process restart and are intentionally
retained, including after logout, to avoid replay. The server remains the
authority for expiration. Linux/macOS directories are owner-only and directory
entries are synced on claim. Windows uses the current user's data directory
and file sync; actual ACL/power-loss behavior still requires native validation.
Never silently clear receipts on error.

This chooses at-most-once UI handoff: a crash between durable claim and display
can suppress the notice rather than show it twice. On the next poll the SDK
reports that receipt as pending ACK; server counts are delivery acceptance,
not proof of visual display or human viewing. Exact-once visual effects across
arbitrary crashes are not guaranteed. Cancellation after a poll response cannot
recall bytes already received; offers are locally capped to 30 seconds and the
SDK subtracts request latency from validity. Native UI and real HTTPS testing
are still required.

Run cargo test --workspace --locked and cargo build -p toastlink-ffi --locked.
