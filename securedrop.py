import threading
import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import os
import socket
import sys
import yaml
server_ip = os.getenv('TCP_SERVER_IP', '127.0.0.1')
server_port = int(os.getenv('TCP_SERVER_PORT', '9999'))
message = os.getenv('TCP_MESSAGE')
commandlist = ["add", "list", "send", "exit", "help"]
contact_count = 0
hostname = os.getenv("CLIENT_NAME", socket.gethostname())
online_people = {} # who is online
class user: # a user will map strings to specific data
    def __init__(self, dictionary):
        self.encryptedAESKey = dictionary["encryptedAESKey"]
        self.nonce = dictionary["nonce"]
        self.tag = dictionary["tag"]
        self.ciphertext = dictionary["ciphertext"]

# we will hash the password for security reasons using SHA256 and generate a salt
def hashpassword(password):
    salt = os.urandom(16) # generate 16 random bytes and hash it below
    key = PBKDF2(password, salt, dkLen = 32, count = 1000000, hmac_hash_module = SHA256)
    return salt.hex(), key.hex()

# we will verify the password and rehash it to make sure it is authentic
def verifypassword(salt, password):
    salt = bytes.fromhex(salt) # reverse the hex on the salt and rehash (below)
    newhash = PBKDF2(password, salt, dkLen = 32, count = 1000000, hmac_hash_module = SHA256)
    return newhash.hex(), newhash.hex()

# in case no public or private keys exist we will generate them with this function
def generate_keys():
    key = RSA.generate(2048) # 2048-bit key
    private_key = key.export_key() # export it as a private key and write it to file
    with open("private.pem", "wb") as f: f.write(private_key)
    public_key = key.publickey().export_key() # do the same for a public key
    with open("public.pem", "wb") as f: f.write(public_key)
    print("Generated private and public keys successfully.")

# we will encrypt (and decrypt) information about the user using PGP which involves AES and RSA
def encryptinfo(password, email, name):
    try:
        pubkey = RSA.importKey(open("public.pem").read()) # read the public key
        data = f"{password}|{email}|{name}".encode('utf-8')
        AESKey = get_random_bytes(16)
        AESCipher = AES.new(AESKey, AES.MODE_EAX) # generate an AES cipher to encrypt text
        ciphertext, tag = AESCipher.encrypt_and_digest(data) # encrypt the ciphertext using the data
        RSACipher = PKCS1_OAEP.new(pubkey) # generate an RSA Cipher and use it to encrypt the AES key
        encryptedAESKey = RSACipher.encrypt(AESKey) # encrypt the AES key using RSA
        return {
            "encryptedAESKey": encryptedAESKey.hex(),
            "nonce": AESCipher.nonce.hex(),
            "tag": tag.hex(),
            "ciphertext": ciphertext.hex()
        } # this is an entry
    except Exception as e:
        print(f"Encryption failed: {e}")

# we will encrypt (and decrypt) information about the user using PGP which involves AES and RSA
def decryptinfo(encryptedDictionary):
    try:
        privatekey = RSA.importKey(open("private.pem").read())
        # reverse the hex from the values and then obtain the mapped values
        encryptedAESKey =  bytes.fromhex(encryptedDictionary["encryptedAESKey"])
        nonce =  bytes.fromhex(encryptedDictionary["nonce"])
        tag =  bytes.fromhex(encryptedDictionary["tag"])
        ciphertext =  bytes.fromhex(encryptedDictionary["ciphertext"])
        RSACipher = PKCS1_OAEP.new(privatekey) # obtain an RSA cipher with private key
        AESKey = RSACipher.decrypt(encryptedAESKey) # use it to decrypt AES key
        AESCipher = AES.new(AESKey, AES.MODE_EAX, nonce) # generate an AES cipher to decrypt text
        data = AESCipher.decrypt_and_verify(ciphertext, tag) # decrypt the data and decode it below
        decryptedString = data.decode("utf-8")
        password, email, name = decryptedString.split("|") # remove a separator from the data
        return name, email, password # return the decrypted information
    except Exception as e:
        print(f"Decryption failed: {e}")

# the user will register once and generate his/her private key if none exists
def register():
    if not os.path.exists("private.pem"): generate_keys() # generate keys if they do not exist
    fn = input("Enter full name: ")
    ea = input("Enter email address: ")
    password = input("Enter a password: ")
    password2 = input("Enter a password: ")
    if password != password2:
        print("Passwords do not match.")
        return
    salt, hashpass = hashpassword(password)
    newUser = {
        "Name": fn,
        "Email": ea,
        "Salt": salt,
        "Hash": hashpass
    } # new user information (map)
    users = {"users": []} # new map with entries
    if os.path.exists("users.yaml") and os.stat("users.yaml").st_size > 0:
        with open("users.yaml", "r") as f:
            users = yaml.safe_load(f) or {"users": []} # handle empty and nonempty file cases
    users["users"].append(newUser) # now add the new user to the map
    with open("users.yaml", "w") as f:
        yaml.dump(users, f) # dump it in the YAML file
    print("Finished registration.")

# the server will start below and allow listening and acceptance of connections
def startServer():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 9999)) # bind and liston on all interfaces
        s.listen()
        while True:
            conn, address = s.accept() # accept connections and receive info (4096 bits) further
            with conn:
                data = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk: # no data, break
                        break
                    data += chunk # the data received includes that chunk otherwise
                filename = "receivedfile.pgp"
                with open(filename, "wb") as f:
                    f.write(data)
                print(f"Received file from: {address}")
                decryptFileContents(filename)
                conn.sendall(b"ACK") # send the acknowledgement that the info was received

# the user will be able to be seen and heard from with the function below
def broadcast(user):
    email = user["Email"]
    hostname = os.getenv("CLIENT_NAME", socket.gethostname())
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            payload = f"{email}|{hostname}"
            s.sendto(payload.encode("utf-8"), ("255.255.255.255", 8822))
            time.sleep(5)

# with this function a new contact will be added. Contact info will be securely stored and encrypted/decrypted using PGP also.
def add():
    fn = input("Enter recipient's full name: ")
    ea = input("Enter recipient's email address: ")
    pubkey_path = input("Enter recipient's public key file path: ")
    try:
        with open(pubkey_path, "r") as f: pubkey_data = f.read()
    except:
        print("Could not read public key file.")
        return
    encryptedData = encryptinfo("NA", ea, fn)
    if encryptedData is None:
        print("Failed to encrypt contact info.")
        return
    contacts = {}
    if os.path.exists("contacts.yaml") and os.stat("contacts.yaml").st_size > 0:
        with open("contacts.yaml", "r") as f:
            contacts = yaml.safe_load(f) or {}
    contacts[ea] = {
        "info": encryptedData,
        "public_key": pubkey_data
    }
    with open("contacts.yaml", "w") as f: yaml.dump(contacts, f)
    print("Added contact.")

# the user will be able to send the file across to someone else and the data will be encoded.
def send(filepath, contact, current_user):
    email = contact["Email"]
    if email not in online_people:
        print(f"Contact {email} is not online.")
        return
    password = input("Enter your password: ")
    salt = bytes.fromhex(current_user["Salt"])
    hashpass = current_user["Hash"]
    newhash = PBKDF2(password, salt, dkLen = 32, count = 1000000, hmac_hash_module = SHA256)
    if newhash.hex() != hashpass: # see if the hash matches the one on file
        print("Entry incorrect; access denied.")
        return
    host = online_people[email]["host"]
    try:
        recipient_pubkey = contact["Data"]["public_key"] # find the recipient's public key so we can use ot
        data = encryptFileConents(filepath, recipient_pubkey)
        if data is None: return
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
            tcp_socket.settimeout(10)
            tcp_socket.connect((host, 9999))
            tcp_socket.sendall(data.encode("utf-8"))
            try:
                response = tcp_socket.recv(1024)
                if response == b"ACK":
                    print(f"File successfully received by: {email}")
                else:
                    print(f"Unexpected response from {email}: {response}")
            except socket.timeout:
                print(f"No confirmation from {email}")
    except Exception as e:
        print(f"Unable to send to {contact}: {e}")

# before sending the file contents will be encrypted with PGP
def encryptFileConents(filepath, recipient_pubkey):
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        pubkey = RSA.importKey(recipient_pubkey)
        AESKey = get_random_bytes(16)
        AESCipher = AES.new(AESKey, AES.MODE_EAX)
        ciphertext, tag = AESCipher.encrypt_and_digest(data)
        RSACipher = PKCS1_OAEP.new(pubkey)
        encryptedAESKey = RSACipher.encrypt(AESKey)
        data = {
            "key": encryptedAESKey.hex(),
            "nonce": AESCipher.nonce.hex(),
            "tag": tag.hex(),
            "data": ciphertext.hex()
        }
        return yaml.dump(data)
    except FileNotFoundError:
        print("File does not exist: " + filepath)
        return None
    except Exception as e:
        print(e)
        return None

# we will decrypt our received files using private key
def decryptFileContents(filepath):
    try:
        privatekey = RSA.importKey(open("private.pem").read()) # open the private key
        with open(filepath, "rb") as f: data = yaml.safe_load(f) # load the file info
        encryptedAESKey = bytes.fromhex(data["key"]) # get the encrypted AES key so we can decrypt it with RSA
        nonce = bytes.fromhex(data["nonce"])
        tag = bytes.fromhex(data["tag"])
        ciphertext = bytes.fromhex(data["data"])
        RSACipher = PKCS1_OAEP.new(privatekey)
        AESKey = RSACipher.decrypt(encryptedAESKey)
        AESCipher = AES.new(AESKey, AES.MODE_EAX, nonce)
        data = AESCipher.decrypt_and_verify(ciphertext, tag)
        with open("decrypted_output", "wb") as f: f.write(data)
    except Exception as e:
        print(f"Decryption failed: {e}")

# in order to find people on the network we will listen and establish a UDP socket for it
def listenForUsers():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_socket.bind(("0.0.0.0", 8822))
        while True:
            data, address = udp_socket.recvfrom(1024)
            try:
                payload = data.decode("utf-8")
                email, host = payload.split("|")
                online_people[email] = {
                    "host": host,
                    "last_seen": time.time()
                }
            except Exception as e:
                print(f"UDP parse error: {e}")
# here the user will enter the credentials which will be verified with SHA256 hashing
def login():
    with open("users.yaml", "r") as f:
        data = yaml.safe_load(f)
    if not data or "users" not in data:
        print("No users are registered.")
        return None
    attempts = 0
    while attempts < 3: # handle many attempts
        email = input("Enter your email address: ")
        password = input("Enter your password: ")
        for user in data["users"]:
            salt = bytes.fromhex(user["Salt"])
            hashpass = user["Hash"] # obtain the hash and rehash to get original;
            newhash = PBKDF2(password, salt, dkLen = 32, count = 1000000, hmac_hash_module = SHA256)
            if email == user["Email"] and newhash.hex() == hashpass: # if it's a match success
                print("Welcome to SecureDrop.")
                return user # return user that just logged in
        print("Invalid email/password.")
        attempts += 1
    sys.exit(1)

# to make sure we send to someone online we will use this
def findContact(identifier):
    if not os.path.exists("contacts.yaml"): return None
    with open("contacts.yaml", "r") as f: contactData = yaml.safe_load(f) or {}
    if identifier in contactData: return {"Email": identifier, "Data": contactData[identifier]}
    for email, fullData in contactData.items():
        try:
            decryptedName, _, _ = decryptinfo(fullData["info"])
            if decryptedName.lower() == identifier.lower(): return {"Email": email, "Data": fullData}
        except: continue
    return None

# gets the user input
def getInput():
    global message
    entry = input("secure_drop> ").strip()
    if not entry: return
    firstArg = entry.split()[0]
    if firstArg not in commandlist:
        print("Invalid command: " + firstArg)
        return
    elif entry == "exit": sys.exit(1)
    elif entry == "add": add()
    elif entry == "list":
        if not os.path.exists("contacts.yaml"):
            print("Contacts file does not exist.")
        else:
            with open("contacts.yaml", "r") as f:
                contacts = yaml.safe_load(f) or {}
                for email, encryptedData in contacts.items():
                    try:
                        name, _, _ = decryptinfo(encryptedData["info"]) # safely retrieve the decrypted info
                        status = "ONLINE" if email in online_people else "OFFLINE"
                        print(f"Name: {name} | Email: {email} | {status}")
                    except: print(f"Could not decrypt {email}")
    elif entry.startswith("send"):
        parts = entry.split() # split the command into a tuple of elements
        if len(parts) == 3:
            name = parts[1] # the recipient's name
            filepath = parts[2] # where the file lives
            contactDictionary = findContact(name)
            if contactDictionary: # now try to find the contact and see if it exists; if so send!
                send(filepath, contactDictionary, logged_in_user)
            else: print(f"User {name} is not online or is not in your contact list.")
        else: print("Usage send <contact> <filepath>")
    elif entry == "help" or entry == "Help": # print list of available commands
        print("The following commands are available:")
        print("*** add: add a new contact to list of registered contacts.")
        print("*** list: show all registered contacts.")
        print("*** send: send a message to an email address.")
        print("*** help: display this message.")
        print("*** exit: exit the application.")

if not os.path.exists("users.yaml") or os.stat("users.yaml").st_size == 0:
    print("No users are registered with this client.")
    choice = input("Do you want to register a new user? (y/n): ")
    if choice.lower() == "y": register()
else:
    logged_in_user = login()
    if logged_in_user:
        # a few daemons that start broadcasting, listening, and server services
        threading.Thread(target=broadcast, args=(logged_in_user,), daemon=True).start()
        threading.Thread(target=startServer, daemon=True).start()
        threading.Thread(target=listenForUsers, daemon=True).start()
        while True:
            getInput()
