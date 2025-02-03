import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import pickle

BLOCK_SIZE = 32  # AES-256 için


def encrypt(text, key):
    try:
        # Parolayı 32 byte'a tamamla
        key = key.encode().ljust(32)[:32]
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(text.encode(), BLOCK_SIZE))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return f"{iv}:{ct}"
    except Exception as e:
        messagebox.showerror("Hata", f"Şifreleme başarısız: {str(e)}")
        return None


def decrypt(encrypted_text, key):
    try:
        # Parolayı 32 byte'a tamamla
        key = key.encode().ljust(32)[:32]
        iv, ct = encrypted_text.split(":")
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ct)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), BLOCK_SIZE)
        return pt.decode('utf-8')
    except Exception as e:
        messagebox.showerror("Hata", f"Şifre çözme başarısız: {str(e)}")
        return None


class SecretNoteApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secret Note")
        self.root.geometry("720x520")

        # Renk Şeması
        self.colors = {
            "background": "#2E3440",
            "text_bg": "#3B4252",
            "text_fg": "#ECEFF4",
            "button_bg": "#81A1C1",
            "button_fg": "#2E3440",
            "highlight": "#88C0D0",
            "header_bg": "#3B4252"
        }

        self.root.configure(bg=self.colors["background"])
        self.create_widgets()

    def create_widgets(self):
        # Başlık Çerçevesi
        header = tk.Frame(self.root, bg=self.colors["header_bg"], height=60)
        header.pack(fill=tk.X)

        tk.Label(
            header,
            text="🔐 SECRET NOTE",
            font=('Arial', 18, 'bold'),
            bg=self.colors["header_bg"],
            fg=self.colors["text_fg"]
        ).pack(pady=15)

        # Ana İçerik Alanı
        main_frame = tk.Frame(self.root, bg=self.colors["background"])
        main_frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)

        # Metin Alanı
        self.text_area = tk.Text(
            main_frame,
            bg=self.colors["text_bg"],
            fg=self.colors["text_fg"],
            insertbackground=self.colors["text_fg"],
            selectbackground=self.colors["highlight"],
            font=('Courier New', 13),
            wrap=tk.WORD,
            bd=3,
            relief=tk.GROOVE
        )
        self.text_area.pack(fill=tk.BOTH, expand=True)

        # Buton Paneli
        btn_frame = tk.Frame(main_frame, bg=self.colors["background"])
        btn_frame.pack(pady=15)

        buttons = [
            ("Şifrele", self.encrypt_text),
            ("Çöz", self.decrypt_text),
            ("Kaydet", self.save_file),
            ("Yükle", self.load_file)
        ]

        for text, cmd in buttons:
            btn = tk.Button(
                btn_frame,
                text=text,
                command=cmd,
                bg=self.colors["button_bg"],
                fg=self.colors["button_fg"],
                activebackground=self.colors["highlight"],
                activeforeground="#2E3440",
                font=('Arial', 11, 'bold'),
                width=10,
                bd=2,
                relief=tk.RAISED
            )
            btn.pack(side=tk.LEFT, padx=8)

    def get_key(self):
        key = simpledialog.askstring(
            "Güvenlik Anahtarı",
            "Herhangi bir uzunlukta parola girin (en az 8 karakter önerilir):",
            parent=self.root,
            show='*'
        )
        if key and len(key) < 8:
            if not messagebox.askyesno(
                    "Uyarı",
                    "Parolanız 8 karakterden kısa! Devam etmek istiyor musunuz?"
            ):
                return None
        return key

    def encrypt_text(self):
        if key := self.get_key():
            text = self.text_area.get("1.0", tk.END).strip()
            if encrypted := encrypt(text, key):
                self.text_area.delete("1.0", tk.END)
                self.text_area.insert(tk.END, encrypted)

    def decrypt_text(self):
        if key := self.get_key():
            text = self.text_area.get("1.0", tk.END).strip()
            if decrypted := decrypt(text, key):
                self.text_area.delete("1.0", tk.END)
                self.text_area.insert(tk.END, decrypted)

    def save_file(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".secret",
            filetypes=[("Şifreli Dosyalar", "*.secret"), ("Tüm Dosyalar", "*.*")]
        )
        if filename:
            with open(filename, "wb") as f:
                pickle.dump(self.text_area.get("1.0", tk.END), f)

    def load_file(self):
        filename = filedialog.askopenfilename(
            filetypes=[("Şifreli Dosyalar", "*.secret"), ("Tüm Dosyalar", "*.*")]
        )
        if filename:
            with open(filename, "rb") as f:
                self.text_area.delete("1.0", tk.END)
                self.text_area.insert(tk.END, pickle.load(f))


if __name__ == "__main__":
    root = tk.Tk()
    app = SecretNoteApp(root)
    root.mainloop()