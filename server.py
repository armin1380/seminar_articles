import socket, numpy as np, hashlib, os, pickle, struct, threading

# Settings
KDC_IP = '0.0.0.0'
KDC_PORT = 5000
registered_users = {} # { IP: Public_Key }

# Kyber-like Toy Parameters
n, q, k = 256, 3329, 2

def get_fixed_matrix():
    """Generates a deterministic matrix A for the entire system"""
    state = np.random.RandomState(42) # Shared seed for matrix A
    return state.randint(0, q, (k, k, n))

def encode_key_to_poly(key_bytes):
    bits = np.unpackbits(np.frombuffer(key_bytes, dtype=np.uint8))
    poly = np.zeros(n, dtype=np.int32)
    poly[:len(bits)] = bits.astype(np.int32) * (q // 2)
    return poly

def encrypt_pqc(pk, session_key):
    """Encrypts the session key using the user's public key"""
    t = pk
    A = get_fixed_matrix()
    m = encode_key_to_poly(session_key)
    
    # Secret randoms for this encryption session
    r = np.random.randint(-1, 2, (k, n))
    e1 = np.random.randint(-1, 2, (k, n))
    e2 = np.random.randint(-1, 2, n)
    
    u = np.mod(np.einsum("ijk,jk->ik", A.transpose(1, 0, 2), r) + e1, q)
    v = np.mod(np.sum(t * r, axis=0) + e2 + m, q)
    return (u, v)

def send_msg(sock, data):
    msg = struct.pack('!I', len(data)) + data
    sock.sendall(msg)

def recv_msg(sock):
    raw_len = sock.recv(4)
    if not raw_len: return None
    msglen = struct.unpack('!I', raw_len)[0]
    data = b""
    while len(data) < msglen:
        chunk = sock.recv(msglen - len(data))
        if not chunk: break
        data += chunk
    return data

def handle_client(conn, addr):
    ip = addr[0]
    print(f"[DEBUG] New connection: {ip}")
    try:
        while True:
            cmd_raw = recv_msg(conn)
            if not cmd_raw: break
            cmd = cmd_raw.decode()
            
            if cmd == "REGISTER":
                pk_data = recv_msg(conn)
                registered_users[ip] = pickle.loads(pk_data)
                print(f"[SUCCESS] User {ip} registered with PK.")
                send_msg(conn, b"REGISTER_OK")

            elif cmd == "LOGIN":
                if ip in registered_users:
                    send_msg(conn, b"LOGIN_OK")
                else:
                    send_msg(conn, b"NOT_FOUND")

            elif cmd == "GET_TICKET":
                dest_ip = recv_msg(conn).decode()
                if dest_ip in registered_users:
                    # Generate a random 32-byte Session Key
                    session_key = os.urandom(32)
                    # Encrypt for both parties
                    ticket_src = encrypt_pqc(registered_users[ip], session_key)
                    ticket_dst = encrypt_pqc(registered_users[dest_ip], session_key)
                    
                    response = pickle.dumps((ticket_src, ticket_dst, session_key.hex()))
                    send_msg(conn, response)
                    print(f"[TICKET] Issued for {ip} -> {dest_ip}")
                else:
                    send_msg(conn, b"DEST_NOT_FOUND")
    except Exception as e:
        print(f"[ERROR] Handler error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((KDC_IP, KDC_PORT))
    server.listen(5)
    print(f"[*] KDC Server active on port {KDC_PORT}...")
    while True:
        c, a = server.accept()
        threading.Thread(target=handle_client, args=(c, a)).start()
