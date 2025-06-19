import socket
import threading
import json

# Store connected clients: username -> socket
clients = {}

# Store public keys: username -> public_key_pem (string)
public_keys = {}

# Lock for thread-safe operations
lock = threading.Lock()

def broadcast_user_list():
    """Send updated user list + their public keys to all connected clients"""
    with lock:
        users_info = [
            {"username": user, "public_key": public_keys[user]} 
            for user in clients.keys()
        ]
        data = json.dumps({"type": "user_list", "users": users_info}).encode()
        for sock in clients.values():
            try:
                sock.send(data)
            except:
                pass


def handle_client(client_socket):
    try:
        # Step 1: Receive username and public key JSON
        data = client_socket.recv(4096).decode()
        info = json.loads(data)
        username = info["username"]
        user_pubkey = info["public_key"]

        with lock:
            clients[username] = client_socket
            public_keys[username] = user_pubkey

        print(f"[+] {username} connected")

        # Broadcast updated user list
        broadcast_user_list()

        # Listen for incoming messages from this client
        while True:
            msg_data = client_socket.recv(4096)
            if not msg_data:
                break

            msg_json = json.loads(msg_data.decode())

            # Expected format:
            # {
            #   "to": "recipient_username",
            #   "from": "sender_username",
            #   "message": "<encrypted_message_base64>"
            # }

            recipient = msg_json.get("to")
            sender = msg_json.get("from")
            encrypted_msg = msg_json.get("message")

            with lock:
                recipient_socket = clients.get(recipient)

            if recipient_socket:
                try:
                    # Forward message to recipient
                    recipient_socket.send(msg_data)
                    print(f"[>] {sender} -> {recipient}: forwarded")
                except Exception as e:
                    print(f"[!] Error sending message to {recipient}: {e}")

    except Exception as e:
        print(f"[!] Exception with client: {e}")

    finally:
        # Client disconnected, cleanup
        with lock:
            disconnected_user = None
            for user, sock in clients.items():
                if sock == client_socket:
                    disconnected_user = user
                    break
            if disconnected_user:
                del clients[disconnected_user]
                del public_keys[disconnected_user]
                print(f"[-] {disconnected_user} disconnected")
                broadcast_user_list()
        client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 9999))
    server.listen(5)
    print("[*] Server listening on port 9999")

    while True:
        client_sock, addr = server.accept()
        print(f"[+] Connection from {addr}")
        client_thread = threading.Thread(target=handle_client, args=(client_sock,))
        client_thread.start()

if __name__ == "__main__":
    start_server()
