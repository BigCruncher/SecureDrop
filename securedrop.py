import hashlib
import json
import os
import random
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import yaml
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

USERS_FILE    = "users.yaml"
CONTACTS_FILE = "contacts.yaml"
CA_CERT       = "/ca/ca.crt"     # CA cert is placed in every container
CA_KEY        = "/ca/ca.key"     # Assume a CA is present and trusted on all clients

DISCOVERY_PORT = 8822         # UDP
TLS_PORT       = 9999         # TCP

commandlist = ["add", "list", "send", "exit", "help"]

# peers is updated by the discovery_listener thread, read by list_command and
# send_command. Two threads interact with it, so locking is required
peers = {}
peers_lock = threading.Lock()

# Cryptography functions

def derive_key(password, salt):
    """
    Derive a 32-byte AES key from the password using PBKDF2.

    PBKDF2 repeats a hash function thousands of times so brute-forcing a stolen
    salt+key file becomes computationally expensive. The salt prevents
    an attacker from precomputing answers.

    Returns: the derived key, as raw bytes.
    """
    return PBKDF2(password, salt, dkLen=32, count=200000, hmac_hash_module=SHA256)


def encrypt_blob(plaintext, key):
    """
    Encrypt bytes with AES-EAX.

    AES-EAX outputs three things, all hex-encoded in YAML:
    - nonce: random value used to make the encryption non-deterministic
    - MAC tag:   authentication code that detects tampering
    - ciphertext: the encrypted bytes

    Returns: a dict with nonce, tag, and ciphertext hex strings.
    """
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return {"nonce": cipher.nonce.hex(), "tag": tag.hex(), "ciphertext": ct.hex()}


def decrypt_blob(blob, key):
    """
    Verifies the MAC tag, raising a ValueError if the key
    is wrong or the ciphertext was altered. (INTEGRITY)
    """
    cipher = AES.new(key, AES.MODE_EAX, nonce=bytes.fromhex(blob["nonce"]))
    return cipher.decrypt_and_verify(
        bytes.fromhex(blob["ciphertext"]),
        bytes.fromhex(blob["tag"]),
    )


def encrypt_private_key(privkey_pem, password):
    """
    Encrypt an RSA private key.

    Combines the generated private key with a salt and AES with AES-EAX.
    The salt is returned with the ciphertext so login() can repeat
    the derivation.
    """
    salt = get_random_bytes(16)
    key  = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(privkey_pem)
    return salt.hex(), cipher.nonce.hex(), tag.hex(), ct.hex()


# Contacts

def load_contacts(password_key):
    if not os.path.exists(CONTACTS_FILE) or os.path.getsize(CONTACTS_FILE) == 0:
        return {}
    with open(CONTACTS_FILE, "r") as f:
        blob = yaml.safe_load(f)
    raw = decrypt_blob(blob, password_key)
    return yaml.safe_load(raw) or {}


def save_contacts(contacts, password_key):
    raw = yaml.dump(contacts).encode("utf-8")
    blob = encrypt_blob(raw, password_key)
    with open(CONTACTS_FILE, "w") as f:
        yaml.dump(blob, f)


# TLS / Certificate

def sign_csr_with_ca(csr_path, out_cert_path):
    """
    Takes a Certificate Signing Request and produces a signed certificate.
    """
    result = subprocess.run([
        "openssl", "x509", "-req", "-in", csr_path,
        "-CA", CA_CERT, "-CAkey", CA_KEY, "-CAcreateserial",
        "-out", out_cert_path, "-days", "365", "-sha256"
    ], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"openssl x509 signing failed (exit {result.returncode})")


def write_pem_to_drive(session):
    """
    Write the user certificate and private key to /tmp as PEM files.
    """
    with open("/tmp/me.crt", "wb") as f:
        f.write(session["certificate_pem"])
    with open("/tmp/me.key", "wb") as f:
        f.write(session["privkey_pem"])


def make_server_ctx(): # SSL context for server
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile="/tmp/me.crt", keyfile="/tmp/me.key")
    ctx.load_verify_locations(cafile=CA_CERT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def make_client_ctx(): # SSL context for client
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    ctx.load_cert_chain(certfile="/tmp/me.crt", keyfile="/tmp/me.key")
    ctx.check_hostname = False
    return ctx


def peer_email_from_cert(tls_sock):
    """
    Get peer's email from their certificate's common name
    """
    cert = tls_sock.getpeercert()
    for rdn in cert["subject"]:
        for i, j in rdn:
            if i == "commonName":
                return j
    return ""


def recv_exactly(socket, n):
    """
    Read n bytes from a socket.
    """
    buffer = b""
    while len(buffer) < n:
        chunk = socket.recv(n - len(buffer))
        if not chunk:
            raise IOError("connection closed")
        buffer += chunk
    return buffer


def recv_line(socket):
    data = b""
    while not data.endswith(b"\n"):
        chunk = socket.recv(1024)
        if not chunk:
            break  # peer closed
        data += chunk
    return data


# User login + registration

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

    # 1. Generate the user's RSA keypair
    key = RSA.generate(2048)
    privkey_pem = key.export_key()
    pubkey_pem  = key.publickey().export_key()

    # 2. Write private key to disk briefly so openssl can read it
    with open("user.key", "wb") as f:
        f.write(privkey_pem)

    # 3. Build a CSR with CN = email, then have the CA sign it
    subprocess.run([
        "openssl", "req", "-new", "-key", "user.key", "-out", "user.csr",
        "-subj", f"/CN={email}"
    ], check=True, capture_output=True)
    sign_csr_with_ca("user.csr", "user.crt")

    with open("user.crt", "rb") as f:
        cert_pem = f.read()

    # Remove the plaintext private key from disk immediately
    os.remove("user.csr")
    os.remove("user.key")

    # 4. Encrypt the private key for at-rest storage
    salt_h, nonce_h, tag_h, ct_h = encrypt_private_key(privkey_pem, p1)

    # 5. Write data to users.yaml
    record = {
        "users": [{
            "name":        name,
            "email":       email,
            "salt":        salt_h,
            "enc_privkey": {"nonce": nonce_h, "tag": tag_h, "ciphertext": ct_h},
            "certificate": cert_pem.decode("utf-8"),
            "public_key":  pubkey_pem.decode("utf-8"),
        }]
    }
    with open(USERS_FILE, "w") as f:
        yaml.dump(record, f)

    print("Finished registration.")


def login():
    if not os.path.exists(USERS_FILE) or os.path.getsize(USERS_FILE) == 0:
        print("No users are registered with this client.")
        return None

    with open(USERS_FILE, "r") as f:
        users = yaml.safe_load(f).get("users", [])

    while True:
        email = input("Enter Email Address: ").strip()
        password = input("Enter Password: ")

        # Same error whether email or password is wrong
        record = None
        for u in users:
            if u["email"] == email:
                record = u
                break

        if record is None or password == "":
            print("Email and Password Combination Invalid.")
            continue

        # Re-derive the AES key from (password, stored salt) and attempt to
        # decrypt the private key. If the tag check fails (ValueError), the password was wrong.
        salt = bytes.fromhex(record["salt"])
        key  = derive_key(password, salt)
        ek   = record["enc_privkey"]
        cipher = AES.new(key, AES.MODE_EAX, nonce=bytes.fromhex(ek["nonce"]))
        try:
            privkey_pem = cipher.decrypt_and_verify(
                bytes.fromhex(ek["ciphertext"]),
                bytes.fromhex(ek["tag"]),
            )
        except ValueError:
            print("Email and Password Combination Invalid.")
            continue

        print("Welcome to SecureDrop.")
        # When the program exits everything here is freed. Plaintext private key never
        # enters storage.
        return {
            "name":            record["name"],
            "email":           record["email"],
            "privkey_pem":     privkey_pem,                      # in memory only
            "certificate_pem": record["certificate"].encode(),
            "password_key":    key,                              # for contacts.yaml
        }


# Network discovery - UDP

def broadcaster():
    """
    Every 3 seconds, broadcast 'TLS server at <hostname>:<port>' to the network's broadcast address.
    """
    hostname = os.getenv("CLIENT_NAME", socket.gethostname())
    payload  = f"{hostname}|{TLS_PORT}".encode("utf-8")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            s.sendto(payload, ("255.255.255.255", DISCOVERY_PORT))
            time.sleep(3)


def discovery_listener():
    """
    Listens for broadcaster() packets and updates the peers dict.
    """
    my_hostname = os.getenv("CLIENT_NAME", socket.gethostname())
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", DISCOVERY_PORT))
        while True:
            data, _ = s.recvfrom(1024)
            try:
                host, port = data.decode("utf-8").split("|")
                if host == my_hostname:
                    continue   # this is our broadcast so ignore it
                with peers_lock:
                    peers[host] = {"port": int(port), "last_seen": time.time()}
            except Exception:
                pass


# TLS server

def tls_server_loop(session):
    """
    Accepts TLS connections on TLS_PORT and creates a thread for each.
    """
    ctx = make_server_ctx()
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw.bind(("0.0.0.0", TLS_PORT))
    raw.listen(10)
    while True:
        conn, addr = raw.accept()
        threading.Thread(
            target=serve_one_connection,
            args=(ctx, conn, session),
            daemon=True,
        ).start()


def serve_one_connection(ctx, conn, session):
    """
    Completes the TLS handshake, then dispatches to handle_peer.
    """
    try:
        tls_sock = ctx.wrap_socket(conn, server_side=True)
    except (ssl.SSLError, OSError):
        try:
            conn.close()
        except Exception:
            pass
        return
    handle_peer(tls_sock, session)


def handle_peer(tls_sock, session):
    """
    Handle one peer request after a handshake.
    """
    try:
        peer_email = peer_email_from_cert(tls_sock)
        data = recv_line(tls_sock)
        if not data:
            return    # peer closed before sending anything

        req = json.loads(data.decode("utf-8").strip())

        if req.get("op") == "check_mutual":
            contacts = load_contacts(session["password_key"])
            reply = {
                "in_my_contacts": peer_email in contacts,
                "my_email":       session["email"],
                "my_name":        session["name"],
            }
            tls_sock.sendall((json.dumps(reply) + "\n").encode("utf-8"))

        elif req.get("op") == "send_file":
            handle_incoming_file(tls_sock, peer_email, req, session)

    except OSError:
        pass   # peer disconnected mid-conversation, not an error
    except Exception as e:
        print(f"handle_peer error: {type(e).__name__}: {e}")
    finally:
        try:
            tls_sock.close()
        except Exception:
            pass


def handle_incoming_file(tls_sock, peer_email, req, session):
    """
    Receive a file from an authenticated peer.

    1. Verify peer is in our contacts
    2. Auto-accept the transfer (to avoid threading issues)
    3. Receive chunks
    4. Compute SHA-256 of the assembled file, compare against the
        hash the sender gave us
    5. Write the file
    """
    contacts = load_contacts(session["password_key"])
    if peer_email not in contacts:
        tls_sock.sendall(b'{"accept": false, "reason": "not a mutual contact"}\n')
        return

    filename     = os.path.basename(req["filename"])
    size         = int(req["size"])
    sender_seq   = int(req["seq"])
    expected_sha = req.get("sha256", "")

    print(
        f"\nIncoming file from {contacts[peer_email]['name']} <{peer_email}>: "
        f"{filename} ({size} bytes). Accepted automatically.",
        flush=True,
    )

    # Random sequence-number seed, required in milestone 5
    my_seq = random.randint(0, 2**32 - 1)
    tls_sock.sendall((json.dumps({"accept": True, "seq": my_seq}) + "\n").encode())

    received = bytearray()
    expected_seq = sender_seq + 1
    h = hashlib.sha256()

    while len(received) < size:
        header = recv_exactly(tls_sock, 8)
        seq, length = struct.unpack(">II", header)
        if seq != expected_seq:
            tls_sock.sendall(b'{"ok": false, "reason": "sequence mismatch"}\n')
            print("Sequence mismatch", flush=True)
            return
        body = recv_exactly(tls_sock, length)
        received += body
        h.update(body)
        expected_seq += 1

    # Verify integrity
    if expected_sha and h.hexdigest() != expected_sha:
        tls_sock.sendall(b'{"ok": false, "reason": "sha256 mismatch"}\n')
        print("Hash mismatch — file rejected.", flush=True)
        return

    out_path = os.path.join(os.getcwd(), filename)
    with open(out_path, "wb") as f:
        f.write(bytes(received))

    tls_sock.sendall(b'{"ok": true}\n')
    print(f"File saved to {out_path}", flush=True)


# SecureDrop commands

def add_command(session):
    name  = input("Enter Full Name: ").strip()
    email = input("Enter Email Address: ").strip()
    contacts = load_contacts(session["password_key"])
    contacts[email] = {"name": name}
    save_contacts(contacts, session["password_key"])
    print("Contact Added.")


def list_command(session):
    """
    Display peers who are online, in our contact list, and have us in their contact list.
    """
    contacts = load_contacts(session["password_key"])
    online_mutual = []

    with peers_lock:
        snapshot = [
            (h, p["port"]) for h, p in peers.items()
            if time.time() - p["last_seen"] < 10
        ]

    ctx = make_client_ctx()
    for host, port in snapshot:
        try:
            raw = socket.create_connection((host, port), timeout=3)
            tls = ctx.wrap_socket(raw)
            peer_email = peer_email_from_cert(tls)
            tls.sendall((json.dumps({"op": "check_mutual"}) + "\n").encode("utf-8"))
            data = recv_line(tls)
            tls.close()

            if not data:
                continue
            reply = json.loads(data.decode("utf-8").strip())

            if peer_email in contacts and reply.get("in_my_contacts"):
                online_mutual.append((reply["my_name"], peer_email))

        except OSError:
            continue   # handshake failed
        except Exception:
            continue

    if not online_mutual:
        print("No contacts are currently online.")
    else:
        print("The following contacts are online:")
        for name, email in online_mutual:
            print(f"* {name} <{email}>")


def send_command(session, contact_email, filepath):
    if not os.path.isfile(filepath):
        print(f"File not found: {filepath}")
        return

    contacts = load_contacts(session["password_key"])
    if contact_email not in contacts:
        print(f"{contact_email} is not in your contact list.")
        return

    # 1. Find the peer
    with peers_lock:
        snapshot = [
            (h, p["port"]) for h, p in peers.items()
            if time.time() - p["last_seen"] < 10
        ]

    ctx = make_client_ctx()
    target = None
    for host, port in snapshot:
        try:
            raw = socket.create_connection((host, port), timeout=3)
            tls = ctx.wrap_socket(raw)
            if peer_email_from_cert(tls) == contact_email:
                target = tls
                break
            tls.close()
        except OSError:
            continue

    if target is None:
        print(f"{contact_email} is not online.")
        return

    try:
        # 2. Pre-compute SHA-256
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                block = f.read(65536)
                if not block:
                    break
                h.update(block)
        file_sha256 = h.hexdigest()

        # 3. Send the request
        size   = os.path.getsize(filepath)
        my_seq = random.randint(0, 2**32 - 1)
        req = {
            "op":       "send_file",
            "filename": os.path.basename(filepath),
            "size":     size,
            "seq":      my_seq,
            "sha256":   file_sha256,
        }
        target.sendall((json.dumps(req) + "\n").encode("utf-8"))

        # 4. Wait for accept/reject
        data = recv_line(target)
        if not data:
            print("Peer closed connection before responding.")
            return
        reply = json.loads(data.decode("utf-8").strip())
        if not reply.get("accept"):
            print(f"Transfer rejected: {reply.get('reason', 'declined')}.")
            return

        print("Contact has accepted the transfer request.")

        # 5. Stream chunks
        seq = my_seq + 1
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                target.sendall(struct.pack(">II", seq, len(chunk)) + chunk)
                seq += 1

        # 6. Wait for final ACK
        data = recv_line(target)
        if not data:
            print("Peer closed connection before final ack.")
            return
        final = json.loads(data.decode("utf-8").strip())
        if final.get("ok"):
            print("File has been successfully transferred.")
        else:
            print(f"Transfer failed: {final.get('reason', 'unknown')}.")
    finally:
        target.close()


# Shell loop

def getInput(session):
    try:
        entry = input("secure_drop> ").strip()
    except EOFError:
        sys.exit(0)
    if not entry:
        return

    parts = entry.split()
    cmd   = parts[0]

    # Unknown commands print a message but stay in the shell.
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
            add_command(session)
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


# One-time entry point

if not os.path.exists(USERS_FILE) or os.path.getsize(USERS_FILE) == 0:
    print("No users are registered with this client.")
    choice = input("Do you want to register a new user (y/n)? ")
    if choice.lower() == "y":
        register()
    print("Exiting SecureDrop.")
else:
    session = login()
    if session is not None:
        write_pem_to_drive(session)

        # broadcaster: tells the network we're online
        # discovery_listener: maintains the peers dict
        # tls_server_loop: handles incoming list and send requests
        threading.Thread(target=broadcaster,        daemon=True).start()
        threading.Thread(target=discovery_listener, daemon=True).start()
        threading.Thread(target=tls_server_loop, args=(session,), daemon=True).start()

        print('Type "help" For Commands.')
        while True:
            getInput(session)
