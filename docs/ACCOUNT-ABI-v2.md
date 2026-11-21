# Account ABI v2

The account client speaks the ToastRAM account-device v1 protocol. Existing toastlink ABI and pairing records remain independent.
Link the DLL import library and include `toast_account_v2.h`. Calls are blocking. Run network operations on a worker.
The caller owns every successful open or call handle. Query the byte size with copy, provide a buffer of that size, then release the handle.
Unknown or previously released handles return protocol error. Output is UTF-8 JSON without a trailing NUL.

Open takes an object with origin and optional ca_pem. The latter must come from an independent operator trust channel.
Default trust uses native system roots and verifies the HTTPS hostname. Redirects and transparent HTTP retries are disabled.
Use a configurable default of https://accounts.raznet.online. Only account v1 endpoint paths on the discovered issuer are accepted.

Every call takes an object with an op field. The operations and other fields are:

| Operation | Fields | Result |
|---|---|---|
| authorize | device_name | user_code, verification_url, expires_in, interval |
| poll, restore, identity | | account_id, username, device_id, scope |
| disconnect | | null after remote revocation and local cleanup |
| forget_local | | null after local cleanup only |
| list_personas, active_persona | | array, or active object/null |
| persona, activate | persona_id | persona |
| blank | activate | persona |
| generate | model, activate | persona |
| update | persona_id, name, profile, expected_revision, actor | persona |
| delete_persona | persona_id, expected_revision, confirm (DELETE) | boolean |
| save_memory | persona_id, content, weight | memory UUID |
| search | persona_id, query, limit | memory array |
| delete_memory | persona_id, memory_id | boolean |
| prepare | persona_id (nullable), messages, memory_query, memory_limit | server-prepared messages, persona_id, memory_count |

Return codes: 0 success, 2 origin/trust policy, 3 protocol/input/handle, 4 transport/TLS, 5 pending, 6 slowdown, 7 denied, 8 expired, 9 login required, 10 revision conflict, 11 no active persona, 12 not found, 13 secure storage, 14 internal failure. Other HTTP statuses return 1000 plus the status.
Display only the verification URL and user code returned by authorize. Poll on a monotonic timer, increasing the interval after slowdown. Polling too soon returns pending locally.
The OS credential store (Windows Credential Manager, macOS Keychain or Linux Secret Service) stores a refresh record bound to issuer, trust configuration, account and device. A per-binding OS file lock serializes rotation.
A durable marker replaces the predecessor before refresh. After an ambiguous rotation the user signs in again. No predecessor is replayed.
Forgetting locally cannot guarantee revocation when the server cannot be reached. Use the account portal to revoke in that case.

The standalone toast_account_v2_forget_local function accepts the same origin and CA options as open and erases the bound local credential without contacting the server.
