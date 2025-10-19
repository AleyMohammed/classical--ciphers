import tkinter as tk
from tkinter import ttk, messagebox
import numpy as np

# --------------------------
# Caesar Cipher
# --------------------------
def caesar_encrypt(plaintext, k):
    result = ""
    for char in plaintext:
        if char.isupper():
            result += chr((ord(char) + k - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + k - 97) % 26 + 97)
        else:
            result += char
    return result

def caesar_decrypt(ciphertext, k):
    return caesar_encrypt(ciphertext, -k)


# --------------------------
# Vigenere Cipher
# --------------------------
def generateKey(string, key):
    key = list(key)
    if len(string) == len(key):
        return key
    else:
        for i in range(len(string) - len(key)):
            key.append(key[i % len(key)])
    return "".join(key)

def vigenere_encrypt(string, key):
    cipher_text = []
    string = string.upper()
    key = key.upper()
    for i in range(len(string)):
        if string[i].isalpha():
            x = (ord(string[i]) + ord(key[i])) % 26
            x += ord('A')
            cipher_text.append(chr(x))
        else:
            cipher_text.append(string[i])
    return "".join(cipher_text)

def vigenere_decrypt(cipher_text, key):
    orig_text = []
    cipher_text = cipher_text.upper()
    key = key.upper()
    for i in range(len(cipher_text)):
        if cipher_text[i].isalpha():
            x = (ord(cipher_text[i]) - ord(key[i]) + 26) % 26
            x += ord('A')
            orig_text.append(chr(x))
        else:
            orig_text.append(cipher_text[i])
    return "".join(orig_text)


# --------------------------
# Playfair Cipher
# --------------------------
def playfair_generate_key_matrix(key):
    key = key.upper().replace("J", "I")
    matrix = []
    used = set()
    for c in key:
        if c not in used and c.isalpha():
            matrix.append(c)
            used.add(c)
    for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c not in used:
            matrix.append(c)
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def playfair_find_position(matrix, char):
    for i, row in enumerate(matrix):
        for j, c in enumerate(row):
            if c == char:
                return i, j
    return None, None

def playfair_encrypt_decrypt(text, key, mode="encrypt"):
    matrix = playfair_generate_key_matrix(key)
    text = text.upper().replace("J", "I")
    text = "".join([c for c in text if c.isalpha()])
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = 'X'
        if i + 1 < len(text):
            b = text[i + 1]
            if a == b:
                b = 'X'
                i -= 1
        pairs.append((a, b))
        i += 2

    result = ""
    for a, b in pairs:
        row1, col1 = playfair_find_position(matrix, a)
        row2, col2 = playfair_find_position(matrix, b)
        if row1 == row2:
            shift = 1 if mode == "encrypt" else -1
            result += matrix[row1][(col1 + shift) % 5]
            result += matrix[row2][(col2 + shift) % 5]
        elif col1 == col2:
            shift = 1 if mode == "encrypt" else -1
            result += matrix[(row1 + shift) % 5][col1]
            result += matrix[(row2 + shift) % 5][col2]
        else:
            result += matrix[row1][col2]
            result += matrix[row2][col1]
    return result


# # --------------------------
# # Substitution Cipher
# # --------------------------
# def substitution_encrypt(plaintext, key):
#     alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#     mapping = {alphabet[i]: key[i] for i in range(26)}
#     result = ""
#     for c in plaintext.upper():
#         if c.isalpha():
#             result += mapping[c]
#         else:
#             result += c
#     return result

# def substitution_decrypt(ciphertext, key):
#     alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#     mapping = {key[i]: alphabet[i] for i in range(26)}
#     result = ""
#     for c in ciphertext.upper():
#         if c.isalpha():
#             result += mapping[c]
#         else:
#             result += c
#     return result


# # --------------------------
# # Hill Cipher (2x2)
# # --------------------------
# def hill_encrypt(plaintext, key_matrix):
#     plaintext = plaintext.upper().replace(" ", "")
#     if len(plaintext) % 2 != 0:
#         plaintext += 'X'
#     cipher_text = ""
#     for i in range(0, len(plaintext), 2):
#         pair = plaintext[i:i+2]
#         vec = np.array([[ord(pair[0]) - 65], [ord(pair[1]) - 65]])
#         result = np.dot(key_matrix, vec) % 26
#         cipher_text += chr(int(result[0][0]) + 65)
#         cipher_text += chr(int(result[1][0]) + 65)
#     return cipher_text

# def hill_decrypt(ciphertext, key_matrix):
#     det = int(np.round(np.linalg.det(key_matrix))) % 26
#     det_inv = None
#     for i in range(26):
#         if (det * i) % 26 == 1:
#             det_inv = i
#             break
#     if det_inv is None:
#         raise ValueError("Key matrix not invertible mod 26")
#     adj = np.round(np.linalg.inv(key_matrix) * np.linalg.det(key_matrix)).astype(int)
#     inv_matrix = (det_inv * adj) % 26
#     plaintext = ""
#     for i in range(0, len(ciphertext), 2):
#         pair = ciphertext[i:i+2]
#         vec = np.array([[ord(pair[0]) - 65], [ord(pair[1]) - 65]])
#         result = np.dot(inv_matrix, vec) % 26
#         plaintext += chr(int(result[0][0]) + 65)
#         plaintext += chr(int(result[1][0]) + 65)
#     return plaintext


# --------------------------
# GUI Functions
# --------------------------
def process_text(mode):
    algo = algo_var.get()
    text = plaintext_entry.get()
    key = key_entry.get()

    if not text or not key:
        messagebox.showerror("Error", "Please enter both plaintext and key!")
        return

    try:
        if algo == "Caesar Cipher":
            k = int(key)
            result = caesar_encrypt(text, k) if mode == "encrypt" else caesar_decrypt(text, k)

        elif algo == "Vigenere Cipher":
            key_full = generateKey(text, key)
            result = vigenere_encrypt(text, key_full) if mode == "encrypt" else vigenere_decrypt(text, key_full)

        elif algo == "Playfair Cipher":
            result = playfair_encrypt_decrypt(text, key, mode)

        elif algo == "Substitution Cipher":
            if len(key) != 26:
                messagebox.showerror("Error", "Key must be 26 letters (A-Z).")
                return
            result = substitution_encrypt(text, key.upper()) if mode == "encrypt" else substitution_decrypt(text, key.upper())

        elif algo == "Hill Cipher":
            elements = list(map(int, key.split()))
            key_matrix = np.array(elements).reshape(2, 2)
            result = hill_encrypt(text, key_matrix) if mode == "encrypt" else hill_decrypt(text, key_matrix)

        else:
            result = "Invalid algorithm selected."

        result_label.config(text=f"Result ({mode.title()}): {result}")

    except Exception as e:
        messagebox.showerror("Error", f"Something went wrong:\n{str(e)}")


# --------------------------
# GUI Design
# --------------------------
root = tk.Tk()
root.title("Classical Cipher Encryption & Decryption")
root.geometry("520x420")
root.resizable(False, False)
root.configure(bg="#f0f0f0")

tk.Label(root, text="Classical Cipher Tool", font=("Arial", 18, "bold"), bg="#f0f0f0").pack(pady=10)

tk.Label(root, text="Choose Cipher:", bg="#f0f0f0", font=("Arial", 12)).pack()
algo_var = tk.StringVar()
algo_menu = ttk.Combobox(root, textvariable=algo_var, state="readonly",
                         values=["Caesar Cipher", "Vigenere Cipher", "Playfair Cipher", "Substitution Cipher", "Hill Cipher"])
algo_menu.current(0)
algo_menu.pack(pady=5)

tk.Label(root, text="Enter Plaintext / Ciphertext:", bg="#f0f0f0", font=("Arial", 12)).pack()
plaintext_entry = tk.Entry(root, width=55)
plaintext_entry.pack(pady=5)

tk.Label(root, text="Enter Key:", bg="#f0f0f0", font=("Arial", 12)).pack()
key_entry = tk.Entry(root, width=55)
key_entry.pack(pady=5)

frame = tk.Frame(root, bg="#f0f0f0")
frame.pack(pady=15)
tk.Button(frame, text="Encrypt", command=lambda: process_text("encrypt"),
          bg="#4CAF50", fg="white", font=("Arial", 12, "bold"), width=12).grid(row=0, column=0, padx=10)
tk.Button(frame, text="Decrypt", command=lambda: process_text("decrypt"),
          bg="#f44336", fg="white", font=("Arial", 12, "bold"), width=12).grid(row=0, column=1, padx=10)

result_label = tk.Label(root, text="Result:", bg="#f0f0f0", font=("Arial", 12, "bold"), wraplength=450, justify="left")
result_label.pack(pady=10)

root.mainloop()
