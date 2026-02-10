# user2f.py - RECEIVER
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

# (Other math functions assumed identical to user1f)
def keygen():
    sk = os.urandom(32)
    pk = (np.zeros((k, k, n)), b'seed') 
    return pk, sk

# ===============================
# Cryptography Utilities
# ===============================

def xor(data: bytes, key: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, key))

def stream_cipher(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """
    Expands the Session Key using SHAKE256 to match the data length.
    """
    seed = key + nonce
    keystream = hashlib.shake_256(seed).digest(len(data))
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
        send_pickle(client, self.pk)
        send_pickle(client, IP)
        print("Registration Request Sent")

    def login(self, IP):
        send(IP)
        print(f"Login Request Sent for {IP}")

    def kerberos_recived(self, sk, client, IP):
        """
        Performs authentication from Receiver side.
        Returns: session_key (bytes) if successful, None otherwise.
        """
        role = "Receiver"
        send(role)

        print("Waiting for ticket from Sender...")
        
        # 1. Receive Ticket forwarded by Sender (via Server)
        Y_ID = recv_pickle(client)
        Y_key = recv_pickle(client)

        # 2. Decrypt Ticket
        # Simulation of Decrypt(sk, Y_key)
        session_key = b'SESSION_KEY_32_BYTES_FIXED____' 
        sender_id_from_ticket = "192.168.1.10" # Placeholder

        # 3. Challenge Response
        # Generate Ra, Encrypt with SessionKey, Send back
        ra = 12345
        # encrypt(ra + 1)
        # send_pickle(client, encrypted_ra_plus_one)

        print("!!!! User Trusted !!!!")
        return session_key

# ========================== Main Execution =======================================

pk, sk = keygen()
A, t = pk
user = User(t, sk, pk)

# ++++++++++++++++ CURRENT MACHINE IP ++++++++++++++++\
IP = "192.168.3.11" # IP of Kali 2

check = "0"
while check != "3":
    check = input("1. Register \t2. Login \t3. Cancel: \n --> ")
    
    if check == "1":
        send("Registration")
        user.register(IP)

    elif check == "2":
        send("login")
        user.login(IP)
        state = input("1. Send \t 2. Receive\t ")

        if state == "1":
            pass # Sender logic

        elif state == "2":
            send("RECEIVER_MODE")
            
            # Perform Authentication and get Session Key
            session_key = user.kerberos_recived(sk, client, IP)

            if session_key:
                print("\n--- Authentication Successful. Waiting for File ---")
                
                try:
                    # 1. Receive the Packet (Filename, Nonce, EncryptedData)
                    packet = recv_pickle(client)
                    
                    if isinstance(packet, tuple) and len(packet) == 3:
                        filename, nonce, encrypted_data = packet
                        
                        print(f"Receiving encrypted file: {filename}")
                        
                        # 2. Decrypt using SessionKey + Nonce
                        # (XOR is symmetric, so we use the same stream_cipher function)
                        decrypted_data = stream_cipher(session_key, nonce, encrypted_data)
                        
                        # 3. Save the file
                        save_name = "received_" + filename
                        with open(save_name, 'wb') as f:
                            f.write(decrypted_data)
                            
                        print(f"File saved as: {save_name}")
                        print(f"First 50 bytes: {decrypted_data[:50]}")
                    else:
                        print("Invalid data format received.")
                        
                except Exception as e:
                    print(f"Error receiving file: {e}")
            else:
                print("Authentication Failed.")

    elif check == "3":
        client.close()
        break
