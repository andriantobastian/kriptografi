import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import os

# Fungsi untuk Vigenère Cipher (Enkripsi dan Dekripsi)


def vigenere_encrypt(plaintext, key):
    result = []
    key = key.upper()
    key_length = len(key)
    for i, char in enumerate(plaintext):
        if char.isalpha():
            shift = ord(key[i % key_length]) - 65
            if char.isupper():
                result.append(chr((ord(char) - 65 + shift) % 26 + 65))
            else:
                result.append(chr((ord(char) - 97 + shift) % 26 + 97))
        else:
            result.append(char)
    return ''.join(result)


def vigenere_decrypt(ciphertext, key):
    result = []
    key = key.upper()
    key_length = len(key)
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = ord(key[i % key_length]) - 65
            if char.isupper():
                result.append(chr((ord(char) - 65 - shift) % 26 + 65))
            else:
                result.append(chr((ord(char) - 97 - shift) % 26 + 97))
        else:
            result.append(char)
    return ''.join(result)

# Fungsi untuk memilih file dan memprosesnya


def select_file(mode):
    file_path = filedialog.askopenfilename(title="Pilih File", filetypes=(
        ("Text Files", "*.txt"), ("All Files", "*.*")))
    if file_path:
        process_file(file_path, mode)

# Fungsi untuk memproses file


def process_file(file_path, mode):
    try:
        with open(file_path, 'r') as file:
            content = file.read()

        key = entry_key.get()

        if mode == 'encrypt':
            encrypted_text = vigenere_encrypt(content, key)
            result_box.delete(1.0, tk.END)  # Clear previous result
            result_box.insert(tk.END, encrypted_text)
        elif mode == 'decrypt':
            decrypted_text = vigenere_decrypt(content, key)
            result_box.delete(1.0, tk.END)  # Clear previous result
            result_box.insert(tk.END, decrypted_text)
        else:
            messagebox.showinfo("Info", "Mode tidak dikenali.")
    except Exception as e:
        messagebox.showerror("Error", f"Terjadi kesalahan: {e}")

# Fungsi untuk menyimpan hasil


def save_to_file():
    cipher_text = result_box.get(1.0, tk.END)
    save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=(
        ("Text Files", "*.txt"), ("All Files", "*.*")))
    if save_path:
        with open(save_path, 'w') as file:
            file.write(cipher_text)
        messagebox.showinfo("Info", "Ciphertext berhasil disimpan!")

# Fungsi untuk menautkan file ke kotak dialog berikutnya


def link_file():
    file_path = filedialog.askopenfilename(title="Pilih File untuk Tautan", filetypes=(
        ("Text Files", "*.txt"), ("All Files", "*.*")))
    if file_path:
        result_box.delete(1.0, tk.END)  # Clear previous result
        result_box.insert(tk.END, f"File terpilih: {file_path}")


# Membuat GUI
root = tk.Tk()
root.title("Enkripsi dan Dekripsi")
root.geometry("500x600")
root.config(bg="#2c3e50")  # Set background color to dark blue

# Judul utama
label_title = tk.Label(root, text="Kelompok 8", bg="#2c3e50",
                       fg="#ecf0f1", font=("Helvetica", 14, "bold"))
label_title.pack(pady=10)

# Membuat frame
frame = tk.Frame(root, bg="#34495e", bd=5)
frame.place(relx=0.5, rely=0.1, relwidth=0.75, relheight=0.8, anchor='n')

# Label dan Entry untuk kunci
label_key = tk.Label(frame, text="Kunci:", bg="#34495e",
                     fg="#ecf0f1", font=("Helvetica", 12, "bold"))
label_key.pack(pady=5)
entry_key = tk.Entry(frame, width=50, font=(
    "Helvetica", 12), bg="#ecf0f1", fg="#2c3e50")
entry_key.pack(pady=5)

# Tombol untuk memilih file untuk Enkripsi
button_select_encrypt = tk.Button(frame, text="Pilih File untuk Enkripsi", command=lambda: select_file(
    'encrypt'), bg="#4CAF50", fg="white", font=("Helvetica", 12, "bold"))
button_select_encrypt.pack(pady=10, fill=tk.X)

# Tombol untuk memilih file untuk Dekripsi
button_select_decrypt = tk.Button(frame, text="Pilih File untuk Dekripsi", command=lambda: select_file(
    'decrypt'), bg="#2980b9", fg="white", font=("Helvetica", 12, "bold"))
button_select_decrypt.pack(pady=10, fill=tk.X)

# Tombol untuk menautkan file ke kotak dialog berikutnya
button_link_file = tk.Button(frame, text="Tautkan File ke Dialog", command=link_file,
                             bg="#e67e22", fg="white", font=("Helvetica", 12, "bold"))
button_link_file.pack(pady=10, fill=tk.X)

# Hasil Enkripsi/Dekripsi
result_box = tk.Text(frame, height=5, width=50, font=(
    "Helvetica", 12), bg="#ecf0f1", fg="#2c3e50")
result_box.pack(pady=5)

# Tombol untuk Menyimpan Ciphertext
button_save = tk.Button(frame, text="Simpan Ciphertext", command=save_to_file,
                        bg="#e67e22", fg="white", font=("Helvetica", 12, "bold"))
button_save.pack(pady=10, fill=tk.X)

root.mainloop()
