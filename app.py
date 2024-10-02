import tkinter as tk
from tkinter import messagebox, filedialog
import numpy as np
from sympy import Matrix
import os


# Vigenère Cipher Standard

def vigenere_encrypt(plain_text, key):
    key = key.lower()
    encrypted = []
    for i, char in enumerate(plain_text.lower()):
        if char.isalpha():
            shift = ord(key[i % len(key)]) - ord('a')
            encrypted.append(
                chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
    return ''.join(encrypted)


def vigenere_decrypt(cipher_text, key):
    key = key.lower()
    decrypted = []
    for i, char in enumerate(cipher_text.lower()):
        if char.isalpha():
            shift = ord(key[i % len(key)]) - ord('a')
            decrypted.append(
                chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
    return ''.join(decrypted)

# Auto-Key Vigenère Cipher


def auto_key_vigenere_encrypt(plain_text, key):
    key = (key + plain_text).lower()[:len(plain_text)]
    encrypted = []
    for i, char in enumerate(plain_text.lower()):
        if char.isalpha():
            shift = ord(key[i]) - ord('a')
            encrypted.append(
                chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
    return ''.join(encrypted)


def auto_key_vigenere_decrypt(cipher_text, key):
    key = key.lower()
    decrypted = []
    for i, char in enumerate(cipher_text.lower()):
        if char.isalpha():
            shift = ord(key[i]) - ord('a')
            decrypted_char = chr(
                (ord(char) - ord('a') - shift) % 26 + ord('a'))
            decrypted.append(decrypted_char)
            key += decrypted_char
    return ''.join(decrypted)

# Playfair Cipher


def create_playfair_matrix(key):
    key = ''.join(filter(str.isalpha, key)).replace('j', 'i').lower()
    key = ''.join(sorted(set(key), key=lambda x: key.index(x)))
    key += ''.join([chr(i) for i in range(97, 123)
                   if chr(i) not in key and chr(i) != 'j'])
    matrix = [key[i:i + 5] for i in range(0, 25, 5)]
    return matrix


def playfair_encrypt(plain_text, key):
    matrix = create_playfair_matrix(key)
    plain_text = plain_text.replace("j", "i").replace(" ", "").lower()
    plain_text = ''.join(filter(str.isalpha, plain_text))

    if len(plain_text) % 2 != 0:
        plain_text += 'x'

    encrypted = []
    for i in range(0, len(plain_text), 2):
        a, b = plain_text[i], plain_text[i + 1]
        row_a, col_a = divmod(''.join(matrix).index(a), 5)
        row_b, col_b = divmod(''.join(matrix).index(b), 5)

        if row_a == row_b:
            encrypted.append(matrix[row_a][(col_a + 1) % 5])
            encrypted.append(matrix[row_b][(col_b + 1) % 5])
        elif col_a == col_b:
            encrypted.append(matrix[(row_a + 1) % 5][col_a])
            encrypted.append(matrix[(row_b + 1) % 5][col_b])
        else:
            encrypted.append(matrix[row_a][col_b])
            encrypted.append(matrix[row_b][col_a])
    return ''.join(encrypted)


def playfair_decrypt(cipher_text, key):
    matrix = create_playfair_matrix(key)
    decrypted = []

    for i in range(0, len(cipher_text), 2):
        a, b = cipher_text[i], cipher_text[i + 1]
        row_a, col_a = divmod(''.join(matrix).index(a), 5)
        row_b, col_b = divmod(''.join(matrix).index(b), 5)

        if row_a == row_b:
            decrypted.append(matrix[row_a][(col_a - 1) % 5])
            decrypted.append(matrix[row_b][(col_b - 1) % 5])
        elif col_a == col_b:
            decrypted.append(matrix[(row_a - 1) % 5][col_a])
            decrypted.append(matrix[(row_b - 1) % 5][col_b])
        else:
            decrypted.append(matrix[row_a][col_b])
            decrypted.append(matrix[row_b][col_a])
    return ''.join(decrypted)

# Hill Cipher with Matrix Inversion


def mod_inverse_matrix(matrix, mod):
    det = int(round(np.linalg.det(matrix)))
    det_inv = pow(det, -1, mod)
    matrix_mod_inv = det_inv * Matrix(matrix).adjugate() % mod
    return np.array(matrix_mod_inv).astype(int)


def hill_encrypt(plain_text, key_matrix):
    n = len(key_matrix)
    text_vector = [ord(char) - ord('a') for char in plain_text]
    text_vector = np.reshape(text_vector, (-1, n))
    encrypted_vector = np.dot(text_vector, key_matrix) % 26
    encrypted_text = ''.join([chr(num + ord('a'))
                             for num in encrypted_vector.flatten()])
    return encrypted_text


def hill_decrypt(cipher_text, key_matrix):
    n = len(key_matrix)
    text_vector = [ord(char) - ord('a') for char in cipher_text]
    text_vector = np.reshape(text_vector, (-1, n))
    key_matrix_inv = mod_inverse_matrix(key_matrix, 26)
    decrypted_vector = np.dot(text_vector, key_matrix_inv) % 26
    decrypted_text = ''.join([chr(num + ord('a'))
                             for num in decrypted_vector.flatten()])
    return decrypted_text

# Super Encryption


def super_encrypt(plain_text, key):
    vigenere_encrypted = vigenere_encrypt(plain_text, key)
    num_cols = len(key)
    num_rows = (len(vigenere_encrypted) + num_cols - 1) // num_cols
    padded_text = vigenere_encrypted.ljust(num_rows * num_cols)
    columns = ['' for _ in range(num_cols)]
    for i in range(num_rows):
        for j in range(num_cols):
            columns[j] += padded_text[i * num_cols + j]
    ciphertext = ''.join(columns)
    return ciphertext


def super_decrypt(cipher_text, key):
    num_cols = len(key)
    num_rows = (len(cipher_text) + num_cols - 1) // num_cols
    columns = [cipher_text[i * num_rows:(i + 1) * num_rows]
               for i in range(num_cols)]
    decrypted_padded_text = ''
    for i in range(num_rows):
        for j in range(num_cols):
            if i < len(columns[j]):
                decrypted_padded_text += columns[j][i]
    plaintext = vigenere_decrypt(decrypted_padded_text.strip(), key)
    return plaintext

# Fungsi Enkripsi


def encrypt_text():
    plain_text = entry_plaintext.get().replace(" ", "").lower()
    key = entry_key.get().lower()
    cipher_type = cipher_choice.get()

    if cipher_type == "Vigenère":
        result = vigenere_encrypt(plain_text, key)
    elif cipher_type == "Auto-Key Vigenère":
        result = auto_key_vigenere_encrypt(plain_text, key)
    elif cipher_type == "Playfair Cipher":
        result = playfair_encrypt(plain_text, key)
    elif cipher_type == "Hill Cipher":
        # Contoh key_matrix untuk Hill Cipher
        # Harus berupa matriks inversibel
        key_matrix = np.array([[6, 24, 1], [13, 16, 10], [20, 17, 15]])
        result = hill_encrypt(plain_text, key_matrix)
    elif cipher_type == "Super Encryption":
        result = super_encrypt(plain_text, key)
    else:
        result = "Pilih cipher yang valid."

    result_box.delete(1.0, tk.END)
    result_box.insert(tk.END, result)

# Fungsi Dekripsi


def decrypt_text():
    cipher_text = entry_plaintext.get().replace(" ", "").lower()
    key = entry_key.get().lower()
    cipher_type = cipher_choice.get()

    if cipher_type == "Vigenère":
        result = vigenere_decrypt(cipher_text, key)
    elif cipher_type == "Auto-Key Vigenère":
        result = auto_key_vigenere_decrypt(cipher_text, key)
    elif cipher_type == "Playfair Cipher":
        result = playfair_decrypt(cipher_text, key)
    elif cipher_type == "Hill Cipher":
        # Sesuaikan dengan matriks kunci
        key_matrix = np.array([[6, 24, 1], [13, 16, 10], [20, 17, 15]])
        result = hill_decrypt(cipher_text, key_matrix)
    elif cipher_type == "Super Encryption":
        result = super_decrypt(cipher_text, key)
    else:
        result = "Pilih cipher yang valid."

    result_box.delete(1.0, tk.END)
    result_box.insert(tk.END, result)


# Fungsi-fungsi enkripsi dan dekripsi (sesuai dengan kode Anda sebelumnya)

# Fungsi untuk Menyimpan Ciphertext ke File
def save_to_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[
                                             ("Text Files", "*.txt"), ("All Files", "*.*")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(result_box.get(1.0, tk.END))
        messagebox.showinfo("Success", "Ciphertext berhasil disimpan!")

# Fungsi untuk Menyimpan Hasil Dekripsi ke File


def save_decrypted_to_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[
                                             ("Text Files", "*.txt"), ("All Files", "*.*")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(result_box.get(1.0, tk.END))
        messagebox.showinfo("Success", "Hasil dekripsi berhasil disimpan!")

# Fungsi untuk menyimpan file


def save_file(content, file_name):
    with open(file_name, 'w') as file:
        file.write(content)


# Membuat GUI
root = tk.Tk()
root.title("Enkripsi dan Dekripsi")
root.geometry("500x600")
root.config(bg="#2c3e50")  # Set background color to dark blue

# Judul utama
label_title = tk.Label(root, text="Kelompok 8", bg="#2c3e50",
                       fg="#ecf0f1", font=("Helvetica", 16, "bold"))
label_title.pack(pady=20)  # Judul utama di bagian atas

# Membuat frame utama untuk mengelompokkan elemen
frame = tk.Frame(root, bg="#34495e", bd=5)
frame.place(relx=0.5, rely=0.1, relwidth=0.75, relheight=0.8, anchor='n')

# Label dan Entry untuk teks
label_plaintext = tk.Label(
    frame, text="Teks:", bg="#34495e", fg="#ecf0f1", font=("Helvetica", 12, "bold"))
label_plaintext.pack(pady=5)
entry_plaintext = tk.Entry(frame, width=50, font=("Helvetica", 12),
                           bg="#ecf0f1", fg="#2c3e50")
entry_plaintext.pack(pady=5)

# Label dan Entry untuk kunci
label_key = tk.Label(frame, text="Kunci:", bg="#34495e",
                     fg="#ecf0f1", font=("Helvetica", 12, "bold"))
label_key.pack(pady=5)
entry_key = tk.Entry(frame, width=50, font=("Helvetica", 12),
                     bg="#ecf0f1", fg="#2c3e50")
entry_key.pack(pady=5)

# Pilihan Cipher
cipher_choice = tk.StringVar(value="Vigenère")
label_cipher = tk.Label(frame, text="Pilih Cipher:",
                        bg="#34495e", fg="#ecf0f1", font=("Helvetica", 12, "bold"))
label_cipher.pack(pady=5)
cipher_menu = tk.OptionMenu(frame, cipher_choice, "Vigenère", "Auto-Key Vigenère",
                            "Playfair Cipher", "Hill Cipher", "Super Encryption")
cipher_menu.config(bg="#ecf0f1", fg="#2c3e50", font=("Helvetica", 12))
cipher_menu.pack(pady=5)

# Tombol untuk Enkripsi
button_encrypt = tk.Button(frame, text="Enkripsi", command=lambda: encrypt_text(),
                           bg="#4CAF50", fg="white", font=("Helvetica", 12, "bold"))
button_encrypt.pack(pady=10, fill=tk.X)

# Tombol untuk Dekripsi
button_decrypt = tk.Button(frame, text="Dekripsi", command=lambda: decrypt_text(),
                           bg="#2980b9", fg="white", font=("Helvetica", 12, "bold"))
button_decrypt.pack(pady=10, fill=tk.X)

# Hasil Enkripsi/Dekripsi
result_box = tk.Text(frame, height=5, width=50, font=("Helvetica", 12),
                     bg="#ecf0f1", fg="#2c3e50")
result_box.pack(pady=5)

# Tombol untuk Menyimpan Ciphertext
button_save = tk.Button(frame, text="Simpan Ciphertext", command=save_to_file,
                        bg="#e67e22", fg="white", font=("Helvetica", 12, "bold"))
button_save.pack(pady=10, fill=tk.X)

root.mainloop()
