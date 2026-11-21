"""Run against a built toastlink CLI using only loopback and disposable identities."""
import ctypes
import io
import secrets
import datetime as dt
import hashlib
import http.server
import ipaddress
import json
import pathlib
import ssl
import subprocess
import sys
import tempfile
import threading
import uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

cli = pathlib.Path(sys.argv[1]).resolve()
from tls_identity import identity, now, pem

import os
with tempfile.TemporaryDirectory() as tmp:
    root = pathlib.Path(tmp)
    ca = identity("Disposable CA")
    key, cert = identity("Disposable server",ca)
    (root/"cert").write_bytes(cert.public_bytes(pem))
    (root/"key").write_bytes(key.private_bytes(pem,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    requests=[]
    consumed=False
    good_grant=False
    client_id=str(uuid.uuid4())
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_POST(self):
            global consumed
            requests.append(self.path)
            assert self.headers["Authorization"]=="Bearer "+file["enrollment"]["token"]
            assert json.load(io.BytesIO(self.rfile.read(int(self.headers["Content-Length"]))))==expected
            if consumed:
                self.send_response(401); body=b'{"error":"enrollment_denied"}'
            elif self.path.endswith("/redeem"):
                consumed=good_grant
                self.send_response(201)
                body=json.dumps(dict(token_type="Bearer",access_token=secrets.token_urlsafe(32),
                    client_id=client_id, server_id=expected["server_id"], scopes=["read"],
                    expires_at=(now+dt.timedelta(hours=1)).isoformat())).encode() if good_grant else b"{}"
            else:
                self.send_response(200)
                body=json.dumps({"status":"eligible","enrollment_id":expected["enrollment_id"]}).encode()
            self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    server=http.server.HTTPServer(("127.0.0.1",0),Handler)
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(root/"cert",root/"key")
    server.socket=tls.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    try:
        file=json.loads((pathlib.Path(__file__).parent/"fixtures/enrollment-v1/sample.toastlink").read_bytes())
        origin=f"https://127.0.0.1:{server.server_port}"
        file["server"]["url"]=origin
        file["enrollment"]["expires_at"]=(now+dt.timedelta(minutes=10)).isoformat()
        file["tls"]["ca_certificate_pem"]=ca[1].public_bytes(pem).decode()
        raw=json.dumps(file).encode(); (root/"file").write_bytes(raw)
        expected=dict(server_id=file["server"]["id"], enrollment_id=file["enrollment"]["id"],
                      file_sha256=hashlib.sha256(raw).hexdigest())
        trust=dict(origin=origin,server_id=expected["server_id"],ca_der_sha256=ca[1].fingerprint(hashes.SHA256()).hex())
        def run(mode, record, consent=""):
            (root/"trust").write_text(json.dumps(record))
            return subprocess.run([cli,mode,root/"file",root/"trust"],input=consent,text=True,capture_output=True,timeout=30,env={**os.environ,"LOCALAPPDATA":str(root)})
        env={**os.environ,"LOCALAPPDATA":str(root)}
        inspect=subprocess.run([cli,"inspect",root/"file"],env=env,text=True,capture_output=True,check=True)
        preview=json.loads(inspect.stdout)
        assert preview["ca_der_sha256"]==trust["ca_der_sha256"] and preview["file_sha256"]==expected["file_sha256"]
        assert file["enrollment"]["token"] not in inspect.stdout and not requests
        def inline(record):
            return subprocess.run([cli,"preflight",root/"file","--verified-tuple",json.dumps(record)],env=env,text=True,capture_output=True,timeout=30)
        for field,value in (("origin","https://other.invalid"),("server_id","1"*32),("ca_der_sha256","1"*64)):
            assert inline(dict(trust,**{field:value})).returncode and not requests
        # Correct trust tuple, wrong certificate presented by the TLS server.
        other_ca=identity("Other disposable CA")[1]
        bad_file=dict(file,tls={"ca_certificate_pem":other_ca.public_bytes(pem).decode()})
        (root/"file").write_text(json.dumps(bad_file))
        assert inline(dict(trust,ca_der_sha256=other_ca.fingerprint(hashes.SHA256()).hex())).returncode and not requests
        (root/"file").write_bytes(raw)
        assert run("preflight",dict(trust,ca_der_sha256="0"*64)).returncode and not requests
        result=run("preflight",trust); assert result.returncode==0 and len(requests)==1, result.stderr
        assert run("pair",trust,"NO\n").returncode and len(requests)==2
        result=run("pair",trust,"PAIR\n")
        assert result.returncode and "RedemptionUncertain" in result.stderr
        assert requests.count("/api/connect/v1/redeem")==1
        good_grant=True
        result=run("pair",trust,"PAIR\n")
        assert result.returncode==0, result.stderr
        locator=f'{origin}|{expected["server_id"]}|{client_id}|{trust["ca_der_sha256"]}'
        assert locator in result.stdout
        descriptor=root/"ToastRAM Connect"/"sessions"/(hashlib.sha256(origin.encode()).hexdigest()+".json")
        saved=json.loads(descriptor.read_bytes())
        assert saved==dict(version=1,origin=origin,locator=locator,ca_pem=file["tls"]["ca_certificate_pem"])
        changed=dict(file,server=dict(file["server"],id="e"*32))
        (root/"file").write_text(json.dumps(changed))
        check=subprocess.run([cli,"inspect",root/"file"],env=env,text=True,capture_output=True,check=True)
        assert json.loads(check.stdout)["previous_binding_changed"]
        before=len(requests)
        assert inline(dict(trust,server_id="e"*32)).returncode and len(requests)==before
        (root/"file").write_bytes(raw)
        replay=inline(trust)
        assert replay.returncode and "Denied" in replay.stderr
        assert requests[-1]=="/api/connect/v1/preflight"
        descriptor.unlink()
        file["enrollment"]["expires_at"]="2000-01-01T00:00:00Z"
        (root/"file").write_text(json.dumps(file))
        prior_requests=len(requests)
        recovery=subprocess.run([cli,"resume",root/"file",root/"trust",client_id],
                                env={**os.environ,"LOCALAPPDATA":str(root)},capture_output=True,timeout=5)
        assert recovery.returncode==0 and json.loads(descriptor.read_bytes())==saved
        assert len(requests)==prior_requests
        # Successful deletion checks that the specific disposable credential existed.
        assert ctypes.windll.advapi32.CredDeleteW(locator+".ToastRAM Connect v1",1,0)
        print("PASS: scoped grant stored and disposable credential removed")
        print("PASS: trust mismatch, verified preflight, cancelled consent, single ambiguous redemption")
    finally:
        server.shutdown(); server.server_close(); thread.join()


