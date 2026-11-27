"""Account SDK integration via its public Windows ABI. Disposable TLS and vault only."""

import ctypes as c
import base64
import copy as deepcopy_module
import struct
import zlib
import hashlib
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
        visual_base="/v1/auth/personas/"+persona["id"]+"/visuals"
        if self.path == visual_base:
            return self.send(200, {"visuals":state.get("visual_metadata", visual_metadata)})
        if self.path in (visual_base+"/avatar", visual_base+"/sprites"):
            is_atlas = self.path.endswith("/sprites")
            body, digest = (atlas_bytes, atlas_hash) if is_atlas else (visual_bytes, visual_hash)
            body += b"changed" if state.get("bad_visual") else b""
            self.send_response(200)
            self.send_header("Content-Type","image/png")
            self.send_header("ETag",'"'+digest+'"')
            if state.get("oversize_visual"):
                self.send_header("Content-Length",str(len(body) + 8*1024*1024))
                self.end_headers()
                return
            self.send_header("Content-Length",str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
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
            if data["memory_limit"]:
                assert data["memory_limit"] == 20
                if data["memory_query"] == "classic fixture":
                    assert "retrieval_mode" not in data
                else:
                    assert data["retrieval_mode"] == "semantic_hybrid"
            else:
                assert "retrieval_mode" not in data
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
        if self.path.endswith("/evidence/store") or self.path.endswith("/evidence/load"):
            key = ("answer_evidence", state["account"], data["persona_id"],
                   data["answer_id"], data["revision"])
            if self.path.endswith("/store"):
                existing = rows.setdefault(key, data["evidence"])
                return self.send(200, {"stored": existing == data["evidence"]})
            return self.send(200, {"evidence": rows.get(key)})
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
visual_bytes=base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+X2uoAAAAASUVORK5CYII=")
visual_hash=hashlib.sha256(visual_bytes).hexdigest()
def png_chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind+data))
# Valid RGBA PNG with a private ancillary chunk to exercise the full 8 MiB transfer.
atlas_header = b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB",2448,1440,8,6,0,0,0))
atlas_data = png_chunk(b"IDAT", zlib.compress((b"\0"+b"\x01\x02\x03\xff"*2448)*1440))
atlas_end = png_chunk(b"IEND", b"")
atlas_bytes = atlas_header + atlas_data + png_chunk(b"raNd", b"\0"*(8*1024*1024-len(atlas_header+atlas_data+atlas_end)-12)) + atlas_end
assert len(atlas_bytes)==8*1024*1024
atlas_hash=hashlib.sha256(atlas_bytes).hexdigest()
states = "idle thinking happy upset searching approval_wait listening talking memory eye_roll facepalm laughing smug surprised yawning waving arms_crossed".split()
timing = dict(zip(states, (155,180,130,175,190,210,165,135,170,170,200,125,190,140,230,150,200)))
manifest = dict(states=states,custom=[],fallback="idle",frames={
    s:[dict(x=i*144,y=r*180,w=144,h=180,ms=timing[s]) for r in range(8)]
    for i,s in enumerate(states)})
one_shot = ["happy","upset"]+states[9:]
version = "toastram.avatar-animation-selection.v2"
selection = dict(version=version,states=states,fallback="idle",
    profiles=["balanced","reserved","playful","expressive"],default_profile="balanced",
    host_phases=["idle","listening","thinking","searching","memory","approval_wait","responding"],
    cue=dict(version=version,affect="neutral joy amusement warmth curiosity confusion annoyance sadness sarcasm excitement".split()+states[9:]),
    cue_scope="current_response_only",
    model_instruction="Optionally supply one structured affect cue alongside your normal response using the advertised enum. Choose an affect consistent with your own persona and this response. Never insert the cue into visible reply text. Do not claim tool or approval states.",
    max_cues_per_response=1,extra_inference_required=False)
playback = dict(version="toastram.avatar-playback.v2",frame_count_per_state=8,frame_ms=timing,
    blend_ms=120,one_shot=one_shot,loop=[s for s in states if s not in one_shot],
    interrupt="host_priority_immediate_cut",clock="host_monotonic_integer_ms",
    transition="two_existing_atlas_frames_crossfade")
visual_metadata = dict(revision=1,avatar=dict(sha256=visual_hash,mime="image/png"),
    sprites=dict(sha256=atlas_hash,mime="image/png"),manifest=manifest,
    studio_review=dict(schema="toastram.avatar-owner-review.v2",persona_id=persona["id"],
        preview_sha256=visual_hash,atlas_sha256=atlas_hash,
        animation_selection=selection,animation_playback=playback))
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
        metadata=operation(client,"visuals",persona_id=persona["id"])
        assert metadata==visual_metadata
        atlas_args=dict(persona_id=persona["id"],kind="sprites",sha256=atlas_hash,mime="image/png")
        atlas_result=operation(client,"visual_asset",**atlas_args)
        assert base64.b64decode(atlas_result["data_base64"],validate=True)==atlas_bytes
        assert len(atlas_result["data_base64"])==4*((len(atlas_bytes)+2)//3)
        assert atlas_result["sha256"]==atlas_hash and atlas_result["mime"]=="image/png"
        state["oversize_visual"]=True
        operation(client,"visual_asset",3,**atlas_args)
        state.pop("oversize_visual")
        operation(client,"visual_asset",3,**dict(atlas_args,kind="expansion"))
        operation(client,"expansion_manifest",3,persona_id=persona["id"])
        state["visual_metadata"]=dict(revision=7,avatar=None,sprites=None,manifest=None)
        assert operation(client,"visuals",persona_id=persona["id"])["revision"]==7
        for field in ("manifest","studio_review"):
            broken=deepcopy_module.deepcopy(visual_metadata)
            broken[field]=None
            state["visual_metadata"]=broken
            operation(client,"visuals",3,persona_id=persona["id"])
        broken=deepcopy_module.deepcopy(visual_metadata)
        broken["manifest"]["frames"]["arms_crossed"][7]["x"]=0
        state["visual_metadata"]=broken
        operation(client,"visuals",3,persona_id=persona["id"])
        state.pop("visual_metadata")
        visual_args=dict(persona_id=persona["id"],kind="avatar",sha256=visual_hash,mime="image/png")
        result=operation(client,"visual_asset",**visual_args)
        assert base64.b64decode(result["data_base64"],validate=True)==visual_bytes
        assert result["sha256"]==visual_hash and result["mime"]=="image/png"
        operation(client,"visual_asset",3,**dict(visual_args,sha256="0"*64))
        state["bad_visual"]=True
        operation(client,"visual_asset",3,**visual_args)
        state["bad_visual"]=False
        operation(client,"visual_asset",12,**dict(visual_args,persona_id=uid()))
        operation(client,"visuals",12,persona_id=uid())
        operation(client,"visual_asset",3,**dict(visual_args,kind="../avatar"))
        operation(client,"visual_asset",3,**dict(visual_args,mime="text/html"))
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
        answer = uid()
        key = dict(persona_id=persona["id"], answer_id=answer, revision=1)
        evidence = {"answer_id": answer, "revision": 1, "sources": []}
        assert operation(client, "store_evidence", evidence=evidence, **key) == {"stored": True}
        assert operation(client, "load_evidence", **key) == {"evidence": evidence}
        assert operation(client, "load_evidence", **dict(key, revision=2)) == {"evidence": None}

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
        for query, extra in (
            ("classic fixture", {}),
            ("hybrid fixture", {"retrieval_mode": "semantic_hybrid"}),
        ):
            prepared = operation(client, "prepare", persona_id=persona["id"],
                                 messages=[], memory_query=query, memory_limit=20, **extra)
            assert prepared["messages"][0]["content"] == "server prepared"
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
