#discord message encryption software
import base64, os, json, tkinter as tk
from tkinter import ttk, messagebox
import pyperclip
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = "enc:v1:"      # prefix so future formats can coexist
KEYBOOK = "keybook.json" # per-contact passphrases (stored locally, plaintext)

def b64(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode().rstrip("=")

def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))

def encrypt_msg(plaintext: str, passphrase: str) -> str:
    salt, nonce = os.urandom(16), os.urandom(12)
    key = derive_key(passphrase, salt)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    token = b"|".join([salt, nonce, ct])
    return VERSION + b64(token)

def decrypt_msg(token: str, passphrase: str) -> str:
    if not token.startswith(VERSION):
        raise ValueError("Unsupported token/version.")
    payload = b64d(token[len(VERSION):])
    try:
        salt, nonce, ct = payload.split(b"|", 2)
    except ValueError:
        raise ValueError("Malformed ciphertext.")
    key = derive_key(passphrase, salt)
    pt = AESGCM(key).decrypt(nonce, ct, None)
    return pt.decode("utf-8")

def load_keybook():
    try:
        with open(KEYBOOK, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception:
        return {}

def save_keybook(kb):
    with open(KEYBOOK, "w", encoding="utf-8") as f:
        json.dump(kb, f, indent=2)

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DM Encrypter (E2EE)")
        self.geometry("760x560")
        self.minsize(700, 520)
        self.keybook = load_keybook()

        # Top: contact + passphrase controls
        top = ttk.Frame(self); top.pack(fill="x", padx=10, pady=(10, 6))
        ttk.Label(top, text="Contact/Alias").grid(row=0, column=0, sticky="w")
        self.alias = ttk.Combobox(top, values=list(self.keybook.keys()))
        self.alias.grid(row=1, column=0, padx=(0, 8), sticky="ew")
        top.columnconfigure(0, weight=1)

        ttk.Label(top, text="Passphrase (kept local)").grid(row=0, column=1, sticky="w")
        self.pass_entry = ttk.Entry(top, show="•")
        self.pass_entry.grid(row=1, column=1, sticky="ew")
        top.columnconfigure(1, weight=2)

        save_btn = ttk.Button(top, text="Save to Keybook", command=self.save_pass)
        save_btn.grid(row=1, column=2, padx=(8, 0))

        # Middle: plaintext / ciphertext panes
        mid = ttk.Frame(self); mid.pack(fill="both", expand=True, padx=10, pady=6)
        left = ttk.Frame(mid); right = ttk.Frame(mid)
        left.pack(side="left", fill="both", expand=True, padx=(0,5))
        right.pack(side="left", fill="both", expand=True, padx=(5,0))

        ttk.Label(left, text="Plaintext").pack(anchor="w")
        self.plain = tk.Text(left, wrap="word", height=12)
        self.plain.pack(fill="both", expand=True)

        ttk.Label(right, text="Ciphertext").pack(anchor="w")
        self.cipher = tk.Text(right, wrap="word", height=12)
        self.cipher.pack(fill="both", expand=True)

        # Buttons
        btns = ttk.Frame(self); btns.pack(fill="x", padx=10, pady=6)
        ttk.Button(btns, text="Encrypt →", command=self.do_encrypt).pack(side="left")
        ttk.Button(btns, text="← Decrypt", command=self.do_decrypt).pack(side="left", padx=6)
        ttk.Button(btns, text="Copy Ciphertext", command=self.copy_cipher).pack(side="right")
        ttk.Button(btns, text="Paste to Plaintext", command=self.paste_plain).pack(side="right", padx=6)

        # Status
        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status, relief="sunken", anchor="w").pack(fill="x", padx=10, pady=(0,10))

        # Autofill passphrase from keybook on alias select
        self.alias.bind("<<ComboboxSelected>>", lambda e: self.load_pass_for_alias())

    def save_pass(self):
        a = self.alias.get().strip()
        p = self.pass_entry.get()
        if not a or not p:
            messagebox.showwarning("Missing", "Alias and passphrase are required.")
            return
        self.keybook[a] = p
        save_keybook(self.keybook)
        self.alias["values"] = list(self.keybook.keys())
        self.status.set(f"Saved passphrase for '{a}' locally.")

    def load_pass_for_alias(self):
        a = self.alias.get().strip()
        if a in self.keybook:
            self.pass_entry.delete(0, tk.END)
            self.pass_entry.insert(0, self.keybook[a])

    def get_pass(self):
        p = self.pass_entry.get()
        if not p:
            raise ValueError("Passphrase is empty.")
        return p

    def do_encrypt(self):
        try:
            pt = self.plain.get("1.0", "end-1c")
            token = encrypt_msg(pt, self.get_pass())
            self.cipher.delete("1.0", tk.END)
            self.cipher.insert("1.0", token)
            self.status.set("Encrypted. You can copy & paste this into Discord.")
        except Exception as e:
            messagebox.showerror("Encrypt error", str(e))

    def do_decrypt(self):
        try:
            token = self.cipher.get("1.0", "end-1c").strip()
            pt = decrypt_msg(token, self.get_pass())
            self.plain.delete("1.0", tk.END)
            self.plain.insert("1.0", pt)
            self.status.set("Decrypted.")
        except Exception as e:
            messagebox.showerror("Decrypt error", str(e))

    def copy_cipher(self):
        data = self.cipher.get("1.0", "end-1c")
        pyperclip.copy(data)
        self.status.set("Ciphertext copied to clipboard.")

    def paste_plain(self):
        self.plain.delete("1.0", tk.END)
        self.plain.insert("1.0", pyperclip.paste())
        self.status.set("Pasted clipboard → plaintext.")

if __name__ == "__main__":
    App().mainloop()


