import socket
import threading
import json
import base64
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from tkinter import scrolledtext, messagebox
import time

# ⚙️ Load khóa
def load_key(filename):
    try:
        with open(filename, 'rb') as f:
            return RSA.import_key(f.read())
    except FileNotFoundError:
        print(f"Error: File {filename} not found. Chạy generate_keys.py để tạo khóa.")
        raise

HOST = '127.0.0.1'
PORT = 5001

try:
    client_private = load_key('client_private.pem')
    client_public = load_key('client_public.pem')
    server_public = None  # Sẽ nhận từ server
except Exception as e:
    print(f"Error loading keys: {e}")
    exit(1)

aes_send = None
aes_receive = None
sock = None

def log(msg):
    log_area.config(state='normal')
    log_area.insert(tk.END, msg + '\n')
    log_area.yview(tk.END)
    log_area.config(state='disabled')

def append_chat(msg):
    chat_area.config(state='normal')
    chat_area.insert(tk.END, msg + '\n')
    chat_area.yview(tk.END)
    chat_area.config(state='disabled')

def exchange_key():
    global aes_send, aes_receive, sock, server_public
    if not sock or not server_public:
        log('❌ Không có kết nối hoặc khóa công khai server')
        return
    try:
        sock.settimeout(5.0)
        log('⏳ Chờ kết nối ổn định...')
        time.sleep(0.5)
        log('📤 Gửi dữ liệu đến server...')
        aes_send = get_random_bytes(32)
        metadata = 'Client|Session'
        h = SHA256.new(metadata.encode())
        signature = pkcs1_15.new(client_private).sign(h)
        cipher_rsa = PKCS1_v1_5.new(server_public)
        encrypted_key = cipher_rsa.encrypt(aes_send)
        packet = {
            'encrypted_key': base64.b64encode(encrypted_key).decode(),
            'signature': base64.b64encode(signature).decode(),
            'metadata': metadata
        }
        sock.send(json.dumps(packet).encode())
        log(f'📥 Chờ dữ liệu từ server...')
        data = sock.recv(4096)
        if not data:
            raise Exception("No data received from server")
        log(f'📥 Nhận dữ liệu từ server: {len(data)} bytes')
        response = json.loads(data.decode())
        if not all(key in response for key in ['encrypted_key', 'signature', 'metadata']):
            raise Exception("Invalid packet format")
        encrypted_key_peer = base64.b64decode(response['encrypted_key'])
        signature_peer = base64.b64decode(response['signature'])
        metadata_peer = response['metadata']

        h_peer = SHA256.new(metadata_peer.encode())
        try:
            pkcs1_15.new(server_public).verify(h_peer, signature_peer)
            log('✔️ Xác thực metadata từ server thành công')
        except:
            log('❌ Lỗi xác thực metadata từ server')
            raise Exception("Invalid metadata signature")

        cipher_rsa = PKCS1_v1_5.new(client_private)
        aes_receive = cipher_rsa.decrypt(encrypted_key_peer, None)
        if not aes_receive:
            raise Exception("Failed to decrypt AES key")
        sock.settimeout(None)
        log('🔑 Trao đổi khóa AES thành công')
    except socket.timeout:
        log('❌ Timeout chờ dữ liệu từ server')
        if sock:
            sock.send('NACK: Timeout'.encode())
    except Exception as e:
        log(f'❌ Lỗi trao đổi khóa: {e}')
        if sock:
            sock.send(f'NACK: Error - {str(e)}'.encode())

def start_client():
    global sock, server_public
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    while True:
        try:
            sock.connect((HOST, PORT))
            log(f'🔗 Đã kết nối đến {HOST}:{PORT}')
            append_chat('[Hệ thống] Đã kết nối')
            break
        except ConnectionRefusedError:
            log('❌ Server chưa sẵn sàng, đang thử lại...')
            time.sleep(1)
    try:
        # Gửi khóa công khai của client
        client_public_pem = client_public.export_key().decode()
        sock.send(json.dumps({'public_key': client_public_pem}).encode())
        log(f'📤 Gửi khóa công khai client: {len(client_public_pem)} bytes')

        # Nhận khóa công khai của server
        data = sock.recv(4096)
        if not data:
            raise Exception("No public key received from server")
        server_public_data = json.loads(data.decode())['public_key']
        server_public = RSA.import_key(server_public_data)
        log(f'📥 Nhận khóa công khai server: {len(server_public_data)} bytes')

        exchange_key()
        threading.Thread(target=receive, daemon=True).start()
    except Exception as e:
        log(f'❌ Lỗi handshake: {e}')
        if sock:
            sock.close()

def send():
    global aes_send, sock
    msg = entry_msg.get()
    if not msg or not aes_send or not sock:
        log('❌ Không thể gửi: Chưa kết nối hoặc khóa AES không sẵn sàng')
        return

    try:
        if not msg.strip():
            log('⚠️ Tin nhắn rỗng, bỏ qua')
            return
        iv = get_random_bytes(16)
        cipher_aes = AES.new(aes_send, AES.MODE_CBC, iv)
        cipher_text = cipher_aes.encrypt(pad(msg.encode(), AES.block_size))

        h = SHA256.new(iv + cipher_text)
        signature = pkcs1_15.new(client_private).sign(h)

        packet = {
            'iv': base64.b64encode(iv).decode(),
            'cipher': base64.b64encode(cipher_text).decode(),
            'hash': h.hexdigest(),
            'signature': base64.b64encode(signature).decode()
        }
        log(f'📤 Gửi tin nhắn: {msg}')
        sock.send(json.dumps(packet).encode())
        append_chat(f'[Client] {msg}')
        entry_msg.delete(0, tk.END)
    except Exception as e:
        log(f'❌ Lỗi gửi tin nhắn: {e}')

def receive():
    global aes_receive, sock
    nack_count = 0
    max_nack = 3  # Giới hạn số lần nhận NACK liên tiếp
    while sock:
        try:
            data = sock.recv(4096)
            if not data:
                log('❌ Kết nối bị ngắt')
                append_chat('[Hệ thống] Đã ngắt kết nối')
                break
            decoded_data = data.decode().strip()
            log(f'📥 Nhận dữ liệu thô: {decoded_data[:50]}...')
            if decoded_data.startswith('NACK:') or decoded_data.startswith('ACK:'):
                log(f'⚠️ Nhận thông báo: {decoded_data}')
                if decoded_data.startswith('ACK:'):
                    append_chat(f'[Server] {decoded_data}')
                nack_count = 0  # Đặt lại khi nhận ACK
                continue
            try:
                if not decoded_data:
                    log('⚠️ Dữ liệu rỗng, bỏ qua')
                    sock.send('NACK: Empty data'.encode())
                    continue
                packet = json.loads(decoded_data)
                iv = base64.b64decode(packet['iv'])
                cipher_text = base64.b64decode(packet['cipher'])
                signature = base64.b64decode(packet['signature'])
                h_recv = packet['hash']

                h = SHA256.new(iv + cipher_text)
                if h.hexdigest() != h_recv:
                    log('❌ Sai hash')
                    sock.send('NACK: Integrity check failed'.encode())
                    continue

                try:
                    pkcs1_15.new(server_public).verify(h, signature)
                    log('✔️ Chữ ký hợp lệ')
                except:
                    log('❌ Sai chữ ký')
                    sock.send('NACK: Invalid signature'.encode())
                    continue

                cipher_aes = AES.new(aes_receive, AES.MODE_CBC, iv)
                plain = unpad(cipher_aes.decrypt(cipher_text), AES.block_size).decode()
                log(f'📥 Giải mã thành công: {plain}')
                append_chat(f'[Server] {plain}')
                sock.send('ACK: Message received'.encode())
                nack_count = 0  # Đặt lại khi nhận dữ liệu hợp lệ
            except json.JSONDecodeError:
                log(f'❌ Dữ liệu không phải JSON: {decoded_data[:50]}...')
                sock.send('NACK: Invalid JSON format'.encode())
                nack_count += 1
                if nack_count >= max_nack:
                    log(f'❌ Quá nhiều NACK, ngắt kết nối')
                    sock.send('NACK: Too many errors'.encode())
                    break
            except Exception as e:
                log(f'❌ Lỗi nhận: {e}')
                sock.send(f'NACK: Error - {str(e)}'.encode())
        except Exception as e:
            log(f'❌ Lỗi socket: {e}')
            break
    if sock:
        sock.close()

# 🔌 GUI
root = tk.Tk()
root.title('Client - Chat Bảo Mật')

chat_area = scrolledtext.ScrolledText(root, width=60, height=20)
chat_area.grid(row=0, column=0, columnspan=3)
chat_area.config(state='disabled')

entry_msg = tk.Entry(root, width=50)
entry_msg.grid(row=1, column=0)

btn_send = tk.Button(root, text='Gửi', command=send)
btn_send.grid(row=1, column=1)

btn_disconnect = tk.Button(root, text='Thoát', command=root.destroy)
btn_disconnect.grid(row=1, column=2)

log_area = scrolledtext.ScrolledText(root, width=60, height=10, fg='blue')
log_area.grid(row=2, column=0, columnspan=3)
log_area.config(state='disabled')

threading.Thread(target=start_client, daemon=True).start()

root.mainloop()