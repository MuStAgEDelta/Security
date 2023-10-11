import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES
import os
import Encrypt_caesar
import Decrypt_caesar
import OneTimen
import ReVerstOneTime
import pdb


global shift_entry

# Funktionen zur Verschlüsselung und Entschlüsselung
def encrypt_file(mode):
    file_path = filedialog.askopenfilename()
    key = b'SuperSecretKey12'  # Gemeinsamer Schlüssel für ECB und CBC
    if mode == 'ECB':
        with open(file_path, 'r') as file:
            content = file.read()
            
        ciphertext = OneTimen.xor_text(content,key)
    elif mode == 'CBC':
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
    elif mode == 'Caesar':
        global shift_entry
        shift= shift_entry.get()
        with open(file_path, 'r') as file:
            content = file.read()
            ciphertext = Encrypt_caesar.encrypt_text(content, shift)
        return
       
    
    with open(file_path + f'_{mode}.txt', 'wb') as encrypted_file:
        file= file_path + f'_{mode}.txt'
        file.write(str(ciphertext))

def decrypt_file(mode):
    file_path = filedialog.askopenfilename()
    key = b'SuperSecretKey12'  # Gemeinsamer Schlüssel für ECB und CBC
    if mode == 'ECB':
        with open(file_path, 'rb') as file:
            content = file.read()
            
        cipher = ReVerstOneTime.xor_text(content,key)
    elif mode == 'CBC':
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
    elif mode == 'Caesar':
        shift= int(entry.get())
        shift = shift_entry.get()
        with open(file_path, 'rb') as file:
            content = file.read()
            ciphertext = Dencrypt_caesar.shift_text(content, shift)
            
        with open(file_path + '_caesar.enc', 'wb') as encrypted_file:
            encrypted_file.write(ciphertext)
        return

    with open(file_path, 'rb') as encrypted_file:
        ciphertext = encrypted_file.read()
        plaintext = cipher.decrypt(ciphertext)
    with open(file_path[:-7], 'wb') as decrypted_file:
        decrypted_file.write(plaintext)


# Funktionen zur Anzeige der ECB, CBC, Caesar und Asymmetrische Fenster
def open_ecb_window():
    ecb_window = tk.Toplevel(root)
    ecb_window.title("ECB Verschlüsselung/Entschlüsselung")
    encrypt_button_ecb = tk.Button(ecb_window, text="Datei verschlüsseln (ECB)", command=lambda: encrypt_file('ECB'))
    decrypt_button_ecb = tk.Button(ecb_window, text="Datei entschlüsseln (ECB)", command=lambda: decrypt_file('ECB'))
    encrypt_button_ecb.pack()
    decrypt_button_ecb.pack()

def open_cbc_window():
    cbc_window = tk.Toplevel(root)
    cbc_window.title("CBC Verschlüsselung/Entschlüsselung")
    encrypt_button_cbc = tk.Button(cbc_window, text="Datei verschlüsseln (CBC)", command=lambda: encrypt_file('CBC'))
    decrypt_button_cbc = tk.Button(cbc_window, text="Datei entschlüsseln (CBC)", command=lambda: decrypt_file('CBC'))
    encrypt_button_cbc.pack()
    decrypt_button_cbc.pack()

def open_caesar_window():
    caesar_window = tk.Toplevel(root)
    caesar_window.title("Caesar Verschlüsselung/Entschlüsselung")
    shift_label = tk.Label(caesar_window, text="Shift-Anzahl:")
    shift_label.pack()
    shift_entry = tk.Entry(caesar_window)
    shift_entry.pack()
    encrypt_button_caesar = tk.Button(caesar_window, text="Datei verschlüsseln (Caesar)", command=lambda: encrypt_file('Caesar'))
    decrypt_button_caesar = tk.Button(caesar_window, text="Datei entschlüsseln (Caesar)", command=lambda: decrypt_file('Caesar'))
    encrypt_button_caesar.pack()
    decrypt_button_caesar.pack()

def open_asymmetric_window():
    asym_window = tk.Toplevel(root)
    asym_window.title("Asymmetrische Verschlüsselung/Entschlüsselung")
    KeyGen_button_AS= tk.Button(asym_window, text= "Generat key Pair", command= lambda: generatkey())
    KeyGen_button_AS.pack()    

root = tk.Tk()
root.title("Wählen Sie Ihre Verschlüsselungs- oder Entschlüsselungsmethode")
root.geometry("600x400")

ecb_button = tk.Button(root, text="ECB", command=open_ecb_window)
cbc_button = tk.Button(root, text="CBC", command=open_cbc_window)
caesar_button = tk.Button(root, text="Caesar", command=open_caesar_window)
asym_button = tk.Button(root, text="Asymmetrisch", command=open_asymmetric_window)


ecb_button.pack()
cbc_button.pack()
caesar_button.pack()
asym_button.pack()

root.mainloop()
