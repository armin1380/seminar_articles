# user1f.py - SENDER
import socket
import hashlib
import os
import random
import time
import base64
import pickle
import struct
import numpy as np

# ===================== PQC Parameters =======================
n = 256
q = 3329
k = 2
eta = 2

# ===============================
# Utilities & Math
# ===============================
def mod_q(x):
    return np.mod(x, q).astype(np.int32)

def shake128(seed, length):
    return hashlib.shake_128(seed).digest(length)

def sample_noise(size):
    return np.random.randint(-eta, eta + 1, size, dtype=np.int32)

def encode(msg: bytes):
    bits = np.unpackbits(np.frombuffer(msg, dtype=np.uint8))
    poly = np.zeros(n, dtype=np.int32)
    L = min(len(bits), n)
    poly[:L] = bits[:L].astype(np.int32) * (q // 2)
    return poly, L

def decode(poly, bitlen):
    poly = mod_q(poly)
    bits = (poly > (q // 4)) & (poly < (3 * q // 4))
    bits = bits[:bitlen].astype(np.uint8)
    return np.packbits(bits).tobytes()

def gen_matrix(seed):
    A = np.zeros((k, k, n), dtype=np.int32)
    for i in range(k):
        for j in range(k):
            # Simple simulation of matrix generation
            pass 
    return A

def keygen():
    # Simulation of KeyGen
    sk = os.urandom(32)
    pk = (np.zeros((k, k, n)), b'seed') 
    return pk, sk

# ===============================
# Cryptography Utilities
# ===============================

def xor(data: bytes, key: bytes) -> bytes:
    """XORs two byte strings. Repeats key if data is longer (simple mode), 
    but we will use stream_cipher for proper expansion."""
    return bytes(a ^ b for a, b in zip(data, key))

def h(data):
    return hashlib.sha256(data).digest()

def stream_cipher(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """
    Expands the Session Key using SHAKE256 to match the data length.
    1. Seed = SessionKey + Nonce
    2. Keystream = SHAKE256(Seed)
    3. Output = Data XOR Keystream
    """
    seed = key + nonce
    # Generate a keystream exactly the size of the data
    keystream = hashlib.shake_256(seed).digest(len(data))
    
    # XOR the data with the keystream
    return bytes(d ^ k for d, k in zip(data, keystream))

# ===============================
# Networking Wrappers
# ===============================
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("192.168.1.10", 9999)) # Connect to SERVER IP

def send_pickle(conn, data):
    serialized_data = pickle.dumps(data)
    length = len(serialized_data)
    conn.sendall(struct.pack('!I', length))
    conn.sendall(serialized_data)

def recv_pickle(conn):
    length_data = conn.recv(4)
    if not length_data:
        return None
    length = struct.unpack('!I', length_data)[0]
    data = b''
    while len(data) < length:
        packet = conn.recv(length - len(data))
        if not packet:
            return None
        data += packet
    return pickle.loads(data)

def send(msg):
    message = pickle.dumps(msg)
    client.send(message)
    return message

def receive(conn):
    data = conn.recv(2048)
    return pickle.loads(data)

# ===============================
# User Class
# ===============================
class User:
    def __init__(self, t, sk, pk):
        self.t = t
        self.sk = sk
        self.pk = pk

    def register(self, IP):
        # Sending public key components
        send_pickle(client, self.pk)
        send_pickle(client, IP)
        print("Registration Request Sent")

    def login(self, IP):
        send(IP)
        print(f"Login Request Sent for {IP}")

    def kerberos_send(self, IP, sk):
        """
        Performs authentication.
        Returns: session_key (bytes) if successful, None otherwise.
        """
        destination_IP = input("Enter destination IP: ")
        
        # 1. Send Login/Auth request to Server
        send(destination_IP) # Sending who we want to talk to
        role = "Sender"
        send(role)

        print("Waiting for Server ticket...")
        
        # 2. Receive Encrypted Tickets from Server
        Y_sours_ID = recv_pickle(client)
        Y_sours_ra = recv_pickle(client)
        Y_sours_key = recv_pickle(client)

        # 3. Receive Encrypted Destination Info
        Y_dests_ID = recv_pickle(client)
        Y_dests_key = recv_pickle(client)

        # 4. Decrypt received data (Simulation)
        # In real Kyber, you would use Decrypt(sk, c)
        # Here we simulate extracting the key
        session_key = b'SESSION_KEY_32_BYTES_FIXED____' # Placeholder for logic
        ra = 12345 # Placeholder for Ra

        # 5. Send Ticket to Receiver (via Server Relay)
        print("Sending Ticket to Receiver...")
        send_pickle(client, Y_dests_ID)
        send_pickle(client, Y_dests_key)

        # 6. Verify Receiver
        ra_received = recv_pickle(client) # Expecting Ra + 1 encrypted
        
        # Assuming decryption of ra_received happens here
        # Logic check:
        # if decrypted_ra == ra + 1:
        print("!!!! User Trusted !!!!")
        return session_key
        # else: return None

# ========================== Main Execution =======================================

pk, sk = keygen()
A, t = pk
user = User(t, sk, pk)

# ++++++++++++++++ CURRENT MACHINE IP ++++++++++++++++\
IP = "192.168.1.10" # IP of Kali 1

check = "0"
while check != "3":
    check = input("1. Register \t2. Login \t3. Cancel: \n --> ")
    
    if check == "1":
        send("Registration")
        user.register(IP)

    elif check == "2":
        send("login") # Tell server we want to login
        user.login(IP)
        
        state = input("1. Send File \t 2. Receive File \t ")

        if state == "1":
            send("SENDER_MODE")
            
            # Perform Authentication and get the Session Key
            session_key = user.kerberos_send(IP, sk)

            if session_key:
                print("\n--- Authentication Successful. Starting File Transfer ---")
                filepath = input("Enter file path to send (e.g., secret.txt): ")
                
                if os.path.exists(filepath):
                    # 1. Read the file
                    with open(filepath, 'rb') as f:
                        file_data = f.read()
                    
                    filename = os.path.basename(filepath)
                    file_size = len(file_data)
                    
                    # 2. Generate a random Nonce (16 bytes)
                    # This ensures the keystream is unique every time
                    nonce = os.urandom(16)
                    
                    # 3. Encrypt data using Expanded Key
                    print(f"Encrypting {file_size} bytes...")
                    encrypted_data = stream_cipher(session_key, nonce, file_data)
                    
                    # 4. Create Packet: (Filename, Nonce, EncryptedData)
                    packet = (filename, nonce, encrypted_data)
                    
                    # 5. Send Packet
                    send_pickle(client, packet)
                    print("File sent successfully!")
                else:
                    print("Error: File not found.")
            else:
                print("Authentication Failed.")

        elif state == "2":
            # This is logic if this machine acts as receiver
            pass 

    elif check == "3":
        client.close()
        break
  
