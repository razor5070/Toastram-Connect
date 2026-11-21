"""Account SDK integration via its public Windows ABI. Disposable TLS and vault only."""

import ctypes as c
import http.server
import json
import pathlib
import secrets
import ssl
import sys
import subprocess
import tempfile
import threading
import time
import uuid
from tls_identity import identity, pem, serialization

dll = c.CDLL(str(pathlib.Path(sys.argv[1]).resolve()))
u64, size = c.c_uint64, c.c_size_t
open_client, call, copy, release = [
    getattr(dll, "toast_account_v2_" + name)
    for name in ("open", "call", "copy", "release")
]
open_client.argtypes = [c.c_char_p, size, c.POINTER(u64)]
call.argtypes = [u64, c.c_char_p, size, c.POINTER(u64)]
copy.argtypes = [u64, c.c_void_p, size, c.POINTER(size)]
release.argtypes = [u64]


def invoke(fn, args, data, status=0):
    raw = json.dumps(data).encode()
    result = u64(123)
    got = fn(*args, raw, len(raw), c.byref(result))
    assert got == status, (data.get("op"), got, status)
    if status:
        assert not result.value
        return
    return result.value


def operation(client, op, status=0, **fields):
    result = invoke(call, [client], dict(op=op, **fields), status)
    if status:
        return
    length = size()
    assert copy(result, None, 0, c.byref(length)) == 0
    buf = c.create_string_buffer(length.value)
    assert copy(result, buf, length.value, c.byref(length)) == 0
    assert release(result) == 0 and release(result) != 0
    return json.loads(buf.raw)


def uid():
    return str(uuid.uuid4())


def token():
    return secrets.token_urlsafe(32)


class Server(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def auth(self):
        return (
            self.headers.get("Authorization") == "Bearer " + state["access"]
            and not state["revoked"]
        )

    def do_GET(self):
        if self.path == "/.well-known/toastram-configuration":
            return self.send(
                200,
                dict(
                    protocol="toastram.account-device",
                    version=1,
                    issuer=origin,
                    verification_uri=origin + "/device",
                    token_endpoint=state.get("endpoint", origin + "/v1/auth/token"),
                    user_endpoint=origin + "/v1/auth/me",
                    device_authorization_endpoint=origin + "/v1/auth/device",
                    revocation_endpoint=origin + "/v1/auth/revoke",
                    scopes_supported=["profile", "persona", "memory"],
                    grant_types_supported=[
                        "refresh_token",
                        "urn:ietf:params:oauth:grant-type:device_code",
                    ],
                ),
            )
        if not self.auth():
            return self.send(401, {"error": "invalid_token"})
        if self.path.endswith("/me"):
            return self.send(
                200,
                dict(
                    account_id=state["account"],
                    device_id=device,
                    username="fixture",
                    scope="profile persona memory",
                ),
            )
        if self.path.endswith("/personas"):
            return self.send(200, {"personas": [persona]})
        if self.path.endswith("/personas/" + persona["id"]):
            return self.send(200, {"persona": persona})
        if self.path.endswith("/personas/active"):
            return self.send(200, {"persona": persona})
        return self.send(404, {"error": "persona_not_found"})

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path.endswith("/device"):
            return self.send(
                200,
                dict(
                    device_code=device_secret,
                    user_code="ABCD-EFGH",
                    verification_uri=origin + "/device",
                    verification_uri_complete=origin + "/device?code=ABCD-EFGH",
                    expires_in=state.get("ttl", 30),
                    interval=1,
                ),
            )
        if self.path.endswith("/token"):
            state["polls"] += 1
            if data.get("grant_type") == "refresh_token":
                if data["refresh_token"] != state["refresh"] or state["revoked"]:
                    return self.send(400, {"error": "invalid_grant"})
                if state.get("interrupt"):
                    state["refresh"] = token()
                    self.close_connection = True
                    return
            else:
                assert data["device_code"] == device_secret
                if state.get("decision"):
                    code = state["decision"]
                    return self.send(
                        429 if code == "slow_down" else 400, {"error": code}
                    )
            state.update(access=token(), refresh=token())
            return self.send(
                200,
                dict(
                    access_token=state["access"],
                    refresh_token=state["refresh"],
                    device_id=device,
                    token_type="Bearer",
                    expires_in=state.pop("access_ttl", 900),
                    scope="profile persona memory",
                ),
            )
        if not self.auth():
            return self.send(401, {"error": "invalid_token"})
        if self.path.endswith("/revoke"):
            assert data["device_id"] == device
            state["revoked"] = True
            return self.send(200, {"revoked": True})
        if self.path.endswith("/prepare"):
            items = data["messages"] or [{"role": "system", "content": "{[persona]}"}]
            messages = [
                dict(item, content="server prepared")
                if item["role"] == "system"
                else item
                for item in items
            ]
            return self.send(
                200, dict(messages=messages, persona_id=persona["id"], memory_count=0)
            )
        if self.path.endswith("/personas/create"):
            assert data["mode"] == "blank" or (
                data["mode"] == "generate" and data["model"] == "fixture"
            )
            return self.send(201, {"persona": persona})
        if data.get("persona_id") != persona["id"]:
            if "/memories/" in self.path:
                return self.send(400, {"error": "invalid_query_or_persona"})
            return self.send(404, {"error": "persona_not_found"})
        if self.path.endswith("/activate"):
            return self.send(200, {"persona": dict(persona, active=True)})
        if self.path.endswith("/update"):
            if data["expected_revision"] != 1:
                return self.send(409, {"error": "revision_conflict"})
            return self.send(
                200, {"persona": dict(persona, revision=2, profile=data["profile"])}
            )
        if self.path.endswith("/save"):
            rows[(state["account"], data["persona_id"])] = dict(
                id=memory, body=data["content"], score=1, weight=data["weight"]
            )
            return self.send(201, dict(saved=True, memory_id=memory))
        if self.path.endswith("/search"):
            hit = rows.get((state["account"], data["persona_id"]))
            return self.send(
                200, dict(count=int(hit is not None), memories=[hit] if hit else [])
            )
        if self.path.endswith("/memories/delete"):
            slot = (state["account"], data["persona_id"])
            hit = rows.get(slot)
            deleted = bool(hit and hit["id"] == data["memory_id"])
            if deleted:
                del rows[slot]
            return self.send(200, dict(deleted=deleted))
        if self.path.endswith("/delete"):
            return self.send(200, dict(deleted=True))
        return self.send(404, {})


rows = {}
device, memory, device_secret = uid(), uid(), token()
persona = dict(id=uid(), name="", profile="", state="blank", revision=1)
state = dict(account=uid(), access=token(), refresh=token(), revoked=False, polls=0)
with tempfile.TemporaryDirectory() as tmp:
    root = pathlib.Path(tmp)
    ca = identity("Account disposable CA")
    key, cert = identity("Loopback", ca)
    (root / "cert").write_bytes(cert.public_bytes(pem))
    (root / "key").write_bytes(
        key.private_bytes(
            pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Server)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(root / "cert", root / "key")
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"https://127.0.0.1:{server.server_port}"
    options = dict(origin=origin, ca_pem=ca[1].public_bytes(pem).decode())
    invoke(open_client, [], dict(options, origin=origin.replace("https", "http")), 2)
    invoke(
        open_client,
        [],
        dict(options, origin=origin.replace("127.0.0.1", "localhost")),
        4,
    )
    invoke(open_client, [], dict(origin=origin), 4)
    state["endpoint"] = "https://other.invalid/v1/auth/token"
    invoke(open_client, [], options, 2)
    del state["endpoint"]
    client = invoke(open_client, [], options)
    try:
        operation(client, "restore", 9)

        def authorize():
            meta = operation(client, "authorize", device_name="disposable fixture")
            assert device_secret not in str(meta) and meta["interval"] == 5
            before = state["polls"]
            operation(client, "poll", 5)
            assert before == state["polls"]
            time.sleep(5.1)

        state["ttl"] = 1
        operation(client, "authorize", device_name="expiring")
        time.sleep(1.1)
        operation(client, "poll", 8)
        state.pop("ttl")
        for decision, expected in [
            ("authorization_pending", 5),
            ("access_denied", 7),
            ("expired_token", 8),
            ("slow_down", 6),
        ]:
            authorize()
            state["decision"] = decision
            operation(client, "poll", expected)
            if decision == "slow_down":
                operation(client, "poll", 5)
        state.pop("decision")
        authorize()
        state["access_ttl"] = 10
        account = operation(client, "poll")
        assert account["account_id"] == state["account"] and set(account) == {
            "account_id",
            "device_id",
            "scope",
            "username",
        }
        previous_refresh = state["refresh"]
        assert operation(client, "identity") == account
        assert previous_refresh != state["refresh"], (
            "near-expiry access did not rotate automatically"
        )
        assert operation(client, "list_personas") == [persona]
        assert operation(client, "persona", persona_id=persona["id"]) == persona
        assert operation(client, "blank", activate=True)["name"] == ""
        assert (
            operation(client, "generate", model="fixture", activate=True)["id"]
            == persona["id"]
        )
        assert operation(client, "activate", persona_id=persona["id"])["active"]
        assert (
            operation(
                client,
                "update",
                persona_id=persona["id"],
                name="",
                profile="edited",
                expected_revision=1,
                actor="user",
            )["revision"]
            == 2
        )
        operation(
            client,
            "delete_persona",
            3,
            persona_id=persona["id"],
            expected_revision=2,
            confirm="no",
        )
        assert operation(
            client,
            "delete_persona",
            persona_id=persona["id"],
            expected_revision=2,
            confirm="DELETE",
        )
        assert operation(client, "active_persona") == persona
        assert (
            operation(
                client, "save_memory", persona_id=persona["id"], content="m", weight=0.5
            )
            == memory
        )
        assert (
            operation(client, "search", persona_id=persona["id"], query="m", limit=1)[
                0
            ]["id"]
            == memory
        )
        operation(client, "search", 1400, persona_id=uid(), query="m", limit=1)
        operation(
            client,
            "update",
            10,
            persona_id=persona["id"],
            name="x",
            profile="",
            expected_revision=0,
            actor="user",
        )
        assert (
            operation(
                client,
                "prepare",
                persona_id=persona["id"],
                messages=[],
                memory_query="",
                memory_limit=0,
            )["messages"][0]["content"]
            == "server prepared"
        )
        # Another issuer (even with the same CA) cannot restore this device.
        old_origin = origin
        other = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Server)
        other.socket = tls.wrap_socket(other.socket, server_side=True)
        threading.Thread(target=other.serve_forever, daemon=True).start()
        try:
            origin = f"https://127.0.0.1:{other.server_port}"
            foreign = invoke(open_client, [], dict(options, origin=origin))
            operation(foreign, "restore", 9)
            release(foreign)
        finally:
            origin = old_origin
            other.shutdown()
            other.server_close()
        if len(sys.argv) > 2:
            prefs = root / "account-selection.json"
            prefs.write_text(json.dumps(options), encoding="utf-8")
            subprocess.run(
                [
                    str(pathlib.Path(sys.argv[2]).resolve()),
                    "--account-loopback",
                    str(prefs),
                ],
                cwd=tmp,
                check=True,
                timeout=60,
            )
        old = state["refresh"]
        release(client)
        client = invoke(open_client, [], options)
        operation(client, "restore")
        assert old != state["refresh"]
        # Simulate another process already consuming the stored predecessor.
        state["refresh"] = token()
        operation(client, "restore", 9)
        authorize()
        operation(client, "poll")
        state["revoked"] = True
        operation(client, "active_persona", 9)
        operation(client, "restore", 9)
        state["revoked"] = False
        authorize()
        operation(client, "poll")
        assert operation(
            client, "delete_memory", persona_id=persona["id"], memory_id=memory
        )
        operation(
            client,
            "save_memory",
            persona_id=persona["id"],
            content="account one",
            weight=0.5,
        )
        state["interrupt"] = True
        operation(client, "restore", 4)
        release(client)
        client = invoke(open_client, [], options)
        before = state["polls"]
        operation(client, "restore", 9)
        assert state["polls"] == before
        state.pop("interrupt")
        authorize()
        operation(client, "poll")
        state["account"] = uid()
        operation(client, "restore", 9)
        authorize()
        operation(client, "poll")
        assert (
            operation(
                client, "search", persona_id=persona["id"], query="account one", limit=1
            )
            == []
        )
        assert not operation(
            client, "delete_memory", persona_id=persona["id"], memory_id=memory
        )
        operation(client, "disconnect")
        assert state["revoked"]
        operation(client, "identity", 9)
        operation(client, "restore", 9)
    finally:
        operation(client, "forget_local")
        release(client)
        server.shutdown()
        server.server_close()
print("PASS: account ABI and disposable HTTPS session lifecycle")
