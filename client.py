import socket
import threading
import json
import base64
import os
from tkinter import *
from tkinter import simpledialog, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

KEYS_DIR = "keys"

class ClientApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Chat Client")
        self.username = None
        self.server_ip = "127.0.0.1"
        self.server_port = 9999
        self.client_socket = None
        self.users_public_keys = {}

        # Load or generate RSA keys
        if not os.path.exists(KEYS_DIR):
            os.makedirs(KEYS_DIR)
        self.private_key = None
        self.public_key = None

        self.load_or_generate_keys()

        # GUI Elements
        self.users_listbox = Listbox(master, height=10)
        self.users_listbox.pack(fill=BOTH, expand=True)

        self.chat_log = Text(master, state=DISABLED, height=15)
        self.chat_log.pack(fill=BOTH, expand=True)

        self.msg_entry = Entry(master)
        self.msg_entry.pack(fill=X, padx=5, pady=5)

        self.send_btn = Button(master, text="Send", command=self.send_message)
        self.send_btn.pack(pady=5)

        # Ask username
        self.ask_username()

    def ask_username(self):
        self.username = simpledialog.askstring("Username", "Enter your username:", parent=self.master)
        if not self.username:
            messagebox.showerror("Error", "Username cannot be empty")
            self.master.destroy()
            return
        self.connect_to_server()

    def load_or_generate_keys(self):
        priv_path = os.path.join(KEYS_DIR, f"{self.username}_private.pem")
        pub_path = os.path.join(KEYS_DIR, f"{self.username}_public.pem")
        if os.path.exists(priv_path) and os.path.exists(pub_path):
            # Load existing keys
            with open(priv_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(pub_path, "rb") as f:
                self.public_key = serialization.load_pem_public_key(f.read())
        else:
            # Generate new keys
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.public_key = self.private_key.public_key()
            # Save keys
            with open(priv_path, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(pub_path, "wb") as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

    def connect_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_ip, self.server_port))
            # Send username and public key
            data = {
                "username": self.username,
                "public_key": self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
            }
            self.client_socket.send(json.dumps(data).encode())
            # Start listening thread
            threading.Thread(target=self.listen_for_messages, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect to server: {e}")
            self.master.destroy()

    def listen_for_messages(self):
        while True:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    break
                msg_json = json.loads(data.decode())

                # Handle user list update
                if msg_json.get("type") == "user_list":
                    users = msg_json.get("users", [])
                    self.update_user_list(users)
                    continue

                # Handle incoming message
                sender = msg_json.get("from")
                encrypted_msg_b64 = msg_json.get("message")
                if sender and encrypted_msg_b64:
                    decrypted_msg = self.decrypt_message(encrypted_msg_b64)
                    self.append_chat(f"{sender}: {decrypted_msg}")

            except Exception as e:
                print(f"Error receiving data: {e}")
                break

    def update_user_list(self, users):
        self.users_listbox.delete(0, END)
        self.users_public_keys = {}
        for user_info in users:
            username = user_info["username"]
            public_key_pem = user_info["public_key"]
            if username != self.username:
                self.users_listbox.insert(END, username)
                # Load public key object and store it
                pub_key = serialization.load_pem_public_key(public_key_pem.encode())
                self.users_public_keys[username] = pub_key

    def send_message(self):
        recipient_idx = self.users_listbox.curselection()
        if not recipient_idx:
            messagebox.showwarning("No Recipient", "Please select a user to send message.")
            return
        recipient = self.users_listbox.get(recipient_idx)

        message = self.msg_entry.get().strip()
        if not message:
            return

        # Encrypt message with recipient's public key
        recipient_pub_key = self.users_public_keys.get(recipient)
        if not recipient_pub_key:
            messagebox.showerror("Error", "Recipient's public key not found.")
            return

        encrypted = recipient_pub_key.encrypt(
            message.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
        )
        encrypted_b64 = base64.b64encode(encrypted).decode()

        msg_data = {
            "to": recipient,
            "from": self.username,
            "message": encrypted_b64
        }
        self.client_socket.send(json.dumps(msg_data).encode())
        self.append_chat(f"You: {message}")
        self.msg_entry.delete(0, END)

    def decrypt_message(self, encrypted_b64):
        try:
            encrypted_bytes = base64.b64decode(encrypted_b64)
            decrypted = self.private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(),
                             label=None)
            )
            return decrypted.decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return "<Failed to decrypt>"

    def append_chat(self, text):
        self.chat_log.config(state=NORMAL)
        self.chat_log.insert(END, text + "\n")
        self.chat_log.see(END)
        self.chat_log.config(state=DISABLED)

if __name__ == "__main__":
    root = Tk()
    app = ClientApp(root)
    root.mainloop()
