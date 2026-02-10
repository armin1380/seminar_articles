from flask import Flask, render_template, request, jsonify
import socket, os, pickle, struct, numpy as np, requests

app = Flask(__name__)

# --- NETWORK CONFIG (Adjust per machine) ---
MY_IP = "192.168.1.10"
DEST_IP = "192.168.3.11"
KDC_IP = "192.168.100.100"
KDC_PORT = 5000
SAVE_DIR = os.path.expanduser("~/received_files/")
if not os.path.exists(SAVE_DIR): os.makedirs(SAVE_DIR)

STATE = {"reg": False, "log": False, "auth": False, "session_key": None}

# --- PQC Logic ---
n, q, k = 256, 3329, 2

def get_fixed_matrix():
    state = np.random.RandomState(42)
    return state.randint(0, q, (k, k, n))

def keygen():
    A = get_fixed_matrix()
    s = np.random.randint(-1, 2, (k, n))
    e = np.random.randint(-1, 2, (k, n))
    t = np.mod(np.einsum("ijk,jk->ik", A, s) + e, q)
    return t, s

def decrypt_pqc(sk, ct):
    u, v = ct
    # Recover message polynomial: m = v - s*u
    dec_poly = np.mod(v - np.sum(u * sk, axis=0), q)
    # Map back to bits: 1 if closer to q/2, 0 if closer to 0
    bits = ((dec_poly > q // 4) & (dec_poly < 3 * q // 4)).astype(np.uint8)
    return np.packbits(bits[:256]).tobytes()

MY_PK, MY_SK = keygen()

def send_msg(sock, data):
    sock.sendall(struct.pack('!I', len(data)) + data)

def recv_msg(sock):
    raw_len = sock.recv(4)
    if not raw_len: return None
    msglen = struct.unpack('!I', raw_len)[0]
    data = b""
    while len(data) < msglen:
        data += sock.recv(msglen - len(data))
    return data

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html', state=STATE)

@app.route('/register', methods=['POST'])
def register():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((KDC_IP, KDC_PORT))
        send_msg(s, b"REGISTER")
        send_msg(s, pickle.dumps(MY_PK))
        if recv_msg(s) == b"REGISTER_OK":
            STATE["reg"] = True
            return jsonify({"status": "success"})
    except Exception as e: return jsonify({"status": "error", "msg": str(e)})

@app.route('/login', methods=['POST'])
def login():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((KDC_IP, KDC_PORT))
        send_msg(s, b"LOGIN")
        if recv_msg(s) == b"LOGIN_OK":
            STATE["log"] = True
            return jsonify({"status": "success"})
    except: pass
    return jsonify({"status": "error", "msg": "Login failed"})

@app.route('/authenticate', methods=['POST'])
def authenticate():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((KDC_IP, KDC_PORT))
        send_msg(s, b"GET_TICKET")
        send_msg(s, DEST_IP.encode())
        data = recv_msg(s)
        ticket_src, ticket_dst, raw_key_hex = pickle.loads(data)
        
        # Decrypt to get the session key
        decrypted_key = decrypt_pqc(MY_SK, ticket_src)
        STATE["session_key"] = decrypted_key
        STATE["auth"] = True
        
        print(f"[DEBUG] Decrypted Session Key: {decrypted_key.hex()[:10]}...")
        return jsonify({"status": "success"})
    except Exception as e: return jsonify({"status": "error", "msg": str(e)})

@app.route('/send_file', methods=['POST'])
def send_file():
    if not STATE["auth"]: return "Not Authenticated", 403
    f = request.files['file']
    content = f.read()
    
    # Simple XOR Encryption with the Decrypted Session Key
    key = STATE["session_key"]
    encrypted = bytes(content[i] ^ key[i % 32] for i in range(len(content)))
    
    try:
        r = requests.post(f"http://{DEST_IP}:4443/receive", 
                          files={'file': (f.filename, encrypted)})
        return r.text
    except: return "Destination Unreachable", 500

@app.route('/receive', methods=['POST'])
def receive():
    if not STATE["auth"]: return "Unauthorized", 401
    f = request.files['file']
    enc_data = f.read()
    
    # Decryption
    key = STATE["session_key"]
    decrypted = bytes(enc_data[i] ^ key[i % 32] for i in range(len(enc_data)))
    
    save_path = os.path.join(SAVE_DIR, f.filename)
    with open(save_path, 'wb') as out:
        out.write(decrypted)
        
    print(f"[SUCCESS] File saved and decrypted at {save_path}")
    return "File received successfully", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4443)
