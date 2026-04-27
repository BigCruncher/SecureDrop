import threading
import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import subprocess
import os
import socket
import sys
import yaml
import ssl
import json
import hashlib
import struct

USERS_FILE = "users.yaml"
CONTACTS_FILE = "contacts.yaml"
CA_CERT = "/ca/ca.crt"   # mounted into the container
CA_KEY  = "/ca/ca.key"   # mounted in for signing CSRs at registration

DISCOVERY_PORT = 8822    # UDP, for broadcasts
TLS_PORT       = 9999    # TCP, for mutual-TLS connections

def broadcaster():
    """Periodically broadcast 'I have a TLS server at <host>:<port>'.
       Identity is proven later via certificate during the TLS handshake."""
    hostname = socket.gethostname()
    payload  = f"{hostname}|{TLS_PORT}".encode("utf-8")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            s.sendto(payload, ("255.255.255.255", DISCOVERY_PORT))
            time.sleep(3)

peers = {}        # hostname -> {"port": int, "last_seen": float}
peers_lock = threading.Lock()

def discovery_listener():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", DISCOVERY_PORT))
        while True:
            data, _ = s.recvfrom(1024)
            try:
                host, port = data.decode("utf-8").split("|")
                with peers_lock:
                    peers[host] = {"port": int(port), "last_seen": time.time()}
            except Exception:
                pass

def write_pem_to_disk(session):
    """ssl.SSLContext.load_cert_chain wants files. Write the in-memory PEMs."""
    with open("/tmp/me.crt", "wb") as f: f.write(session["certificate_pem"])
    with open("/tmp/me.key", "wb") as f: f.write(session["privkey_pem"])

def make_server_ctx():
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile="/tmp/me.crt", keyfile="/tmp/me.key")
    ctx.load_verify_locations(cafile=CA_CERT)
    ctx.verify_mode = ssl.CERT_REQUIRED   # peer MUST present a CA-signed cert
    return ctx

def make_client_ctx():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    ctx.load_cert_chain(certfile="/tmp/me.crt", keyfile="/tmp/me.key")
    ctx.check_hostname = False   # we identify by cert CN, not hostname
    return ctx

def peer_email_from_cert(tls_sock) -> str:
    """Extract CN from the peer's certificate — that's their authenticated email."""
    cert = tls_sock.getpeercert()
    for rdn in cert["subject"]:
        for k, v in rdn:
            if k == "commonName":
                return v
    return ""

def tls_server_loop(session):
    ctx = make_server_ctx()
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw.bind(("0.0.0.0", TLS_PORT))
    raw.listen(10)
    while True:
        conn, addr = raw.accept()
        threading.Thread(
            target=handle_peer,
            args=(ctx.wrap_socket(conn, server_side=True), session),
            daemon=True
        ).start()

def handle_peer(tls_sock, session):
    """Server side: answer a 'are we mutual contacts?' probe."""
    try:
        peer_email = peer_email_from_cert(tls_sock)
        # Read the request (small, single line of JSON ending in \n)
        data = b""
        while not data.endswith(b"\n"):
            chunk = tls_sock.recv(1024)
            if not chunk: return
            data += chunk
        req = json.loads(data.decode("utf-8").strip())

        if req.get("op") == "check_mutual":
            contacts = load_contacts(session["password_key"])
            in_my_list = peer_email in contacts
            reply = {"in_my_contacts": in_my_list,
                     "my_email": session["email"],
                     "my_name": session["name"]}
            tls_sock.sendall((json.dumps(reply) + "\n").encode("utf-8"))
        elif req.get("op") == "send_file":
            # see Milestone 5
            handle_incoming_file(tls_sock, peer_email, req, session)
    finally:
        tls_sock.close()

def list_command(session):
    """Connect to each broadcast peer over mutual-TLS, ask if we're mutual contacts."""
    contacts = load_contacts(session["password_key"])
    online_mutual = []

    with peers_lock:
        snapshot = [(h, p["port"]) for h, p in peers.items()
                    if time.time() - p["last_seen"] < 10]

    ctx = make_client_ctx()
    for host, port in snapshot:
        try:
            raw = socket.create_connection((host, port), timeout=3)
            tls = ctx.wrap_socket(raw)             # mutual-TLS handshake
            peer_email = peer_email_from_cert(tls)

            # Don't bother if peer isn't even in our contacts
            if peer_email not in contacts:
                tls.close(); continue

            req = {"op": "check_mutual"}
            tls.sendall((json.dumps(req) + "\n").encode("utf-8"))
            data = b""
            while not data.endswith(b"\n"):
                chunk = tls.recv(1024)
                if not chunk: break
                data += chunk
            reply = json.loads(data.decode("utf-8").strip())
            tls.close()

            if reply.get("in_my_contacts"):
                online_mutual.append((reply["my_name"], peer_email, host, port))
        except Exception:
            continue   # peer not actually reachable / handshake failed / etc.

    if not online_mutual:
        print("No contacts are currently online.")
    else:
        print("The following contacts are online:")
        for name, email, _, _ in online_mutual:
            print(f"* {name} <{email}>")
    return online_mutual   # milestone 5 reuses host/port from this

def handle_incoming_file(tls_sock, peer_email, req, session):
    contacts = load_contacts(session["password_key"])
    if peer_email not in contacts:
        # Project: "From UA on CA to UC on CC, the transfer should not occur"
        # because UA doesn't have UC as a contact. Silently refuse.
        tls_sock.sendall(b'{"accept": false, "reason": "not a contact"}\n')
        return

    filename   = os.path.basename(req["filename"])  # never trust paths from peer
    size       = int(req["size"])
    sender_seq = int(req["seq"])

    print(f"\nContact '{contacts[peer_email]['name']} <{peer_email}>' is sending a file. Accept (y/n)? ", end="", flush=True)
    answer = input().strip().lower()
    if answer != "y":
        tls_sock.sendall(b'{"accept": false}\n')
        return

    my_seq = int.from_bytes(os.urandom(4), "big")
    tls_sock.sendall((json.dumps({"accept": True, "seq": my_seq}) + "\n").encode())

    # Each chunk is: 4-byte sequence number || 4-byte length || payload
    received = bytearray()
    expected_seq = sender_seq + 1
    while len(received) < size:
        header = recv_exactly(tls_sock, 8)
        seq, length = struct.unpack(">II", header)
        if seq != expected_seq:
            print("Sequence mismatch — possible replay. Aborting.")
            return
        received += recv_exactly(tls_sock, length)
        expected_seq += 1

    out_path = os.path.join(os.getcwd(), filename)
    with open(out_path, "wb") as f:
        f.write(bytes(received))
    print(f"\nFile saved to {out_path}")

def recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise IOError("connection closed")
        buf += chunk
    return buf

commandlist = ["add", "list", "send", "exit", "help"]

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from the password using PBKDF2-HMAC-SHA256."""
    return PBKDF2(password, salt, dkLen=32, count=200000, hmac_hash_module=SHA256)

def encrypt_private_key(privkey_pem: bytes, password: str):
    """Encrypt the user's private key with a key derived from their password.
       Returns (salt_hex, nonce_hex, tag_hex, ciphertext_hex)."""
    salt = get_random_bytes(16)
    key  = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(privkey_pem)
    return salt.hex(), cipher.nonce.hex(), tag.hex(), ct.hex()

def sign_csr_with_ca(csr_path: str, out_cert_path: str):
    """Use the local CA to sign a CSR. Surfaces openssl's own error on failure."""
    result = subprocess.run([
        "openssl", "x509", "-req", "-in", csr_path,
        "-CA", CA_CERT, "-CAkey", CA_KEY, "-CAcreateserial",
        "-out", out_cert_path, "-days", "365", "-sha256"
    ], capture_output=True, text=True)
    if result.returncode != 0:
        print("---- openssl stderr ----")
        print(result.stderr)
        print("---- openssl stdout ----")
        print(result.stdout)
        raise RuntimeError(
            f"openssl x509 signing failed (exit {result.returncode})"
        )

def register():
    if os.path.exists(USERS_FILE) and os.path.getsize(USERS_FILE) > 0:
        print("A user is already registered on this client.")
        return

    name  = input("Enter Full Name: ").strip()
    email = input("Enter Email Address: ").strip()
    p1 = input("Enter Password: ")
    p2 = input("Re-enter Password: ")
    if p1 != p2:
        print("Passwords do not match.")
        return
    print("Passwords Match.")

    # 1. Generate the user's keypair
    key = RSA.generate(2048)
    privkey_pem = key.export_key()
    pubkey_pem  = key.publickey().export_key()

    # 2. Write the private key to a temp file so openssl can read it for the CSR
    with open("user.key", "wb") as f:
        f.write(privkey_pem)
    # 3. Build a CSR with CN = email (this is what mutual-TLS will check)
    subprocess.run([
        "openssl", "req", "-new", "-key", "user.key", "-out", "user.csr",
        "-subj", f"/CN={email}"
    ], check=True, capture_output=True)
    # 4. Have the CA sign it
    sign_csr_with_ca("user.csr", "user.crt")

    with open("user.crt", "rb") as f:
        cert_pem = f.read()
    os.remove("user.csr")  # not needed afterwards
    os.remove("user.key")  # plaintext private key never stays on disk

    # 5. Encrypt the private key with a password-derived key
    salt_h, nonce_h, tag_h, ct_h = encrypt_private_key(privkey_pem, p1)

    record = {
        "users": [{
            "name": name,
            "email": email,
            "salt": salt_h,
            "enc_privkey": {"nonce": nonce_h, "tag": tag_h, "ciphertext": ct_h},
            "certificate": cert_pem.decode("utf-8"),
            "public_key": pubkey_pem.decode("utf-8"),
        }]
    }
    with open(USERS_FILE, "w") as f:
        yaml.dump(record, f)

    print("Finished registration.")

def encrypt_blob(plaintext: bytes, key: bytes) -> dict:
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return {"nonce": cipher.nonce.hex(), "tag": tag.hex(), "ciphertext": ct.hex()}

def decrypt_blob(blob: dict, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_EAX, nonce=bytes.fromhex(blob["nonce"]))
    return cipher.decrypt_and_verify(
        bytes.fromhex(blob["ciphertext"]),
        bytes.fromhex(blob["tag"])
    )

def load_contacts(password_key: bytes) -> dict:
    if not os.path.exists(CONTACTS_FILE) or os.path.getsize(CONTACTS_FILE) == 0:
        return {}
    with open(CONTACTS_FILE, "r") as f:
        blob = yaml.safe_load(f)
    raw = decrypt_blob(blob, password_key)
    return yaml.safe_load(raw) or {}

def save_contacts(contacts: dict, password_key: bytes):
    raw = yaml.dump(contacts).encode("utf-8")
    blob = encrypt_blob(raw, password_key)
    with open(CONTACTS_FILE, "w") as f:
        yaml.dump(blob, f)

def add(session):
    name  = input("Enter Full Name: ").strip()
    email = input("Enter Email Address: ").strip()
    contacts = load_contacts(session["password_key"])
    contacts[email] = {"name": name}   # overwrite if exists, per project spec
    save_contacts(contacts, session["password_key"])
    print("Contact Added.")

# here the user will enter the credentials which will be verified with SHA256 hashing
def login():
    if not os.path.exists(USERS_FILE) or os.path.getsize(USERS_FILE) == 0:
        print("No users are registered with this client.")
        return None

    with open(USERS_FILE, "r") as f:
        users = yaml.safe_load(f).get("users", [])

    while True:
        email = input("Enter Email Address: ").strip()
        password = input("Enter Password: ")

        # Find user record by email; same generic error whether email or password is wrong
        record = next((u for u in users if u["email"] == email), None)
        if record is None or password == "":
            print("Email and Password Combination Invalid.")
            continue

        # Try to decrypt the private key. If it works, password is correct.
        salt = bytes.fromhex(record["salt"])
        key  = derive_key(password, salt)
        ek   = record["enc_privkey"]
        cipher = AES.new(key, AES.MODE_EAX, nonce=bytes.fromhex(ek["nonce"]))
        try:
            privkey_pem = cipher.decrypt_and_verify(
                bytes.fromhex(ek["ciphertext"]),
                bytes.fromhex(ek["tag"])
            )
        except ValueError:
            # Wrong password -> AES-EAX tag check fails
            print("Email and Password Combination Invalid.")
            continue

        print("Welcome to SecureDrop.")
        # Return everything the rest of the session will need in memory
        return {
            "name": record["name"],
            "email": record["email"],
            "privkey_pem": privkey_pem,             # plaintext bytes, in-memory only
            "certificate_pem": record["certificate"].encode(),
            "password_key": key,                    # for encrypting contacts.yaml
        }

def send_command(session, contact_email, filepath):
    """Sender side of file transfer. Mutual-TLS auth + replay-resistant chunks."""
    if not os.path.isfile(filepath):
        print(f"File not found: {filepath}")
        return

    contacts = load_contacts(session["password_key"])
    if contact_email not in contacts:
        # Project scenario 9: UA -> UC where UA doesn't have UC -> "transfer should not occur"
        print(f"{contact_email} is not in your contact list.")
        return

    # Walk the discovery snapshot looking for a peer whose cert CN matches contact_email
    with peers_lock:
        snapshot = [(h, p["port"]) for h, p in peers.items()
                    if time.time() - p["last_seen"] < 10]

    ctx = make_client_ctx()
    target = None
    for host, port in snapshot:
        try:
            raw = socket.create_connection((host, port), timeout=3)
            tls = ctx.wrap_socket(raw)
            if peer_email_from_cert(tls) == contact_email:
                target = tls
                break
            tls.close()                          # wrong peer; try the next one
        except Exception:
            continue

    if target is None:
        print(f"{contact_email} is not online.")
        return

    try:
        size   = os.path.getsize(filepath)
        my_seq = int.from_bytes(os.urandom(4), "big")
        req = {
            "op":       "send_file",
            "filename": os.path.basename(filepath),
            "size":     size,
            "seq":      my_seq,
        }
        target.sendall((json.dumps(req) + "\n").encode("utf-8"))

        # Wait for accept/reject (single line of JSON)
        data = b""
        while not data.endswith(b"\n"):
            chunk = target.recv(1024)
            if not chunk:
                print("Peer closed connection before responding.")
                return
            data += chunk
        reply = json.loads(data.decode("utf-8").strip())
        if not reply.get("accept"):
            print(f"Transfer rejected: {reply.get('reason', 'declined by user')}")
            return

        print("Contact has accepted the transfer request.")

        # Stream the file in 64 KB chunks. Each chunk: 4-byte seq || 4-byte len || payload.
        seq = my_seq + 1
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                target.sendall(struct.pack(">II", seq, len(chunk)) + chunk)
                seq += 1
        print("File has been successfully transferred.")
    finally:
        target.close()


def getInput(session):
    """Read a single command from the user and dispatch it."""
    try:
        entry = input("secure_drop> ").strip()
    except EOFError:
        sys.exit(0)
    if not entry:
        return

    parts = entry.split()
    cmd   = parts[0]

    # Scenario 6: unknown commands must NOT crash or exit
    if cmd not in commandlist:
        print(f"Unknown command: {cmd}")
        return

    if cmd == "exit":
        sys.exit(0)
    elif cmd == "help":
        print('"add"  -> Add a new contact')
        print('"list" -> List all online contacts')
        print('"send" -> Transfer file to contact')
        print('"exit" -> Exit SecureDrop')
    elif cmd == "add":
        try:
            add(session)
        except Exception as e:
            print(f"add failed: {e}")
    elif cmd == "list":
        try:
            list_command(session)
        except Exception as e:
            print(f"list failed: {e}")
    elif cmd == "send":
        if len(parts) != 3:
            print("Usage: send <email> <filepath>")
            return
        try:
            send_command(session, parts[1], parts[2])
        except Exception as e:
            print(f"send failed: {e}")


# ----- Entry point -----
if not os.path.exists(USERS_FILE) or os.path.getsize(USERS_FILE) == 0:
    print("No users are registered with this client.")
    choice = input("Do you want to register a new user (y/n)? ")
    if choice.lower() == "y":
        register()
    print("Exiting SecureDrop.")
else:
    session = login()
    if session is not None:
        # Persist cert + key to /tmp so the SSL contexts can load them as files.
        # These are wiped when the container stops; the plaintext key never lives in /data.
        write_pem_to_disk(session)

        threading.Thread(target=broadcaster,         daemon=True).start()
        threading.Thread(target=discovery_listener,  daemon=True).start()
        threading.Thread(target=tls_server_loop, args=(session,), daemon=True).start()

        print('Type "help" For Commands.')
        while True:
            getInput(session)
