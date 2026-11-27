# Conversation ABI extension V1

Additive to account ABI v2. Existing symbols, legacy authorize payload, error numbers and legacy request limit preserved. New error 15 = quota exhausted, 10 = conflict, 7 = denied, 6 = throttled, 9 = login required. New scoped enrollment via {"op":"authorize_scoped","device_name":"Sona Desktop","scopes":["profile","persona","memory","conversation.read","conversation.write","conversation.generate"]}; add conversation.delete only on explicit user request. Legacy authorize stays legacy. Browser may approve a subset. SDK validates dependencies, returned subset, and refresh scope identity. Legacy stored credentials without scope are treated as legacy; existing nonlegacy credentials without recorded scope need re-enrollment. Scope is persisted with OS credential. No silent upgrade.

Call toast_account_v2_call with {"op":"conversation","action":"changes","args":{"after":0,"limit":100}}. Result is server result field unwrapped, including explicit null. Operation names:
- list: /; args: persona_id view after_id limit
- get: /get; args: conversation_id
- messages: /messages; args: conversation_id after limit
- active_path: /active-path; args: conversation_id expected_revision before limit
- changes: /changes; args: after limit
- selection: /selection; args: persona_id latest
- storage: /storage; args: (none)
- generation_status: /generation/status; args: conversation_id
- generation_draft: /generation/draft; args: conversation_id generation_id
- tool_record: /tool/record; args: conversation_id execution_id
- create: /create; args: operation_id conversation_id persona_id title
- append: /append; args: operation_id conversation_id message_id turn_id parent_id expected_revision content fork
- rename: /rename; args: operation_id conversation_id expected_revision title
- transition: /transition; args: operation_id conversation_id expected_revision action
- purge: /purge; args: operation_id conversation_id expected_revision confirm
- select: /select; args: operation_id conversation_id
- select_path: /select-path; args: operation_id conversation_id expected_revision head_id
- generation_start: /generation/start; args: operation_id conversation_id generation_id expected_revision force
- generation_heartbeat: /generation/heartbeat; args: conversation_id generation_id fence
- generation_checkpoint: /generation/checkpoint; args: operation_id conversation_id generation_id fence version content
- generation_complete: /generation/complete; args: operation_id conversation_id generation_id fence message_id content
- generation_handover: /generation/handover; args: conversation_id generation_id fence
- generation_release: /generation/release; args: conversation_id generation_id fence handover
- tool_claim: /tool/claim; args: operation_id conversation_id generation_id fence execution_id call
- tool_confirm: /tool/confirm; args: operation_id conversation_id generation_id fence execution_id result
- tool_review: /tool/review; args: operation_id conversation_id generation_id fence execution_id acknowledge
- offline_import: /offline/import; args: operation_id account_id device_id persona_id destination_id title messages source_id base_revision base_head

No generic URLs. Same trusted HTTPS origin, no redirects or automatic retries. Caller creates stable UUIDs and retains exact request until receipt. Content pages max 4. Conversation request/response limit 9 MiB, FFI wrapper allows 4096 additional bytes; other operations unchanged. Normal conversation calls serialize on account session lock; keep inference on separate worker, schedule heartbeats independently, avoid long concurrent mutations on same session. Tool claim must return explicit dispatch bool and matching execution ID; never dispatch a restored record or a retry receipt. Caller must validate leases and user authorization before external effects. All other results remain JSON; typed per-operation response validation is deferred.

toast_account_v2_conversation_events(client, after, result) is a new blocking symbol. Run on separate worker. Session lock only held while creating authenticated request, not during network wait. Returns {"cursor":N} or {"cursor":null}. Hint is never an applied cursor. Fetch changes after last durable applied cursor, persist only after local application; reconnect with applied cursor. On stream timeout/error use polling every 10s. No autonomous thread, cancellation, local cache, outbox or replay. If session changes while SSE in flight, caller must discard stale hint using local identity/session epoch. Server one-stream-per-device enforced. No live TLS test yet. Run cargo test --workspace --locked and cargo build -p toastlink-ffi --locked; existing C++ consumers retain ABI.
