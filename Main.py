import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os
import caesar
import OneTimen
import ReVerstOneTime
import pdb
from Crypto.Util.Padding import pad, unpad


def generat_key(mode):

    if mode == 'AS':        
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        file_out = open("privateKey.pem", "wb")
        file_out.write(private_key)
        file_out.close()
        
        public_key = key.publickey().export_key()
        
        file_out = open("publicKey.pem", "wb")
        file_out.write(public_key)
        file_out.close()
        show_feedback("created Key Pair")
        
        
            
            
           
        

# Funktionen zur Verschlüsselung und Entschlüsselung
def encrypt_file(mode):
    file_path = filedialog.askopenfilename()
    key = b'\xfd\t\xca9g\x93\x07\xc3h\x03.\xf5\x9f\x0b\xe9E'  # Gemeinsamer Schlüssel für ECB und CBC
    if mode == 'ECB':
        with open(file_path, 'r') as file:
            content = file.read()
        ciphertext = AES.new(key,AES.MODE_ECB)
        ciphertext = ciphertext.encrypt(pad(content.encode('utf-8'), AES.block_size))
        
    elif mode == 'CBC':
        with open(file_path, 'r') as file:
            content = file.read()
        ciphertext = AES.new(key,AES.MODE_CBC, b'\x1a\xf5\x80\xd3\x6b\x24\x10\xcb\x90\xe7\x7f\x29\xa3\x58\x0d\xc2')
        ciphertext = ciphertext.encrypt(pad(content.encode('utf-8'), AES.block_size))

    elif mode == 'Caesar':
        shift= shift_entry.get()
        with open(file_path, 'r') as file:
            content = file.read()
            ciphertext = caesar.caesar_cipher(content, shift)
            ciphertext = ciphertext.encode()
       
    
    
    elif mode == 'AS':
        file_out = open("encrypted_data.bin", "wb")

        recipient_key = RSA.import_key(open("publicKey.pem").read())
        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_GCM)
        with open(file_path, 'r') as file:
            content = file.read()
        ciphertext, tag = cipher_aes.encrypt_and_digest(content.encode('utf-8'))
        [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
        file_out.close()
        
    with open(file_path + f'_{mode}.txt', 'wb') as encrypted_file:
        encrypted_file.write(ciphertext)
    show_feedback("File was successfully encrypted")
       

def decrypt_file(mode):
    file_path = filedialog.askopenfilename()
    key = b'\xfd\t\xca9g\x93\x07\xc3h\x03.\xf5\x9f\x0b\xe9E'  # Gemeinsamer Schlüssel für ECB und CBC
    if mode == 'ECB':
        with open(file_path, 'rb') as file:
            content = file.read()
        ciphertext = AES.new(key, AES.MODE_ECB)
        plaintext = unpad(ciphertext.decrypt(content), AES.block_size)
        
    elif mode == 'CBC':
        with open(file_path, 'rb') as file:
            content = file.read()
        ciphertext = AES.new(key, AES.MODE_CBC,b'\x1a\xf5\x80\xd3\x6b\x24\x10\xcb\x90\xe7\x7f\x29\xa3\x58\x0d\xc2')
        plaintext = unpad(ciphertext.decrypt(content), AES.block_size)
        
    elif mode == 'Caesar':
        shift= shift_entry.get()
        with open(file_path, 'r') as file:
            content = file.read()
            plaintext = caesar.caesar_decipher(content, shift)
            plaintext = plaintext.encode()
            
        #return
    elif mode == 'AS':
        file_in = open("encrypted_data.bin", "rb")

        private_key = RSA.import_key(open("privateKey.pem").read())

        enc_session_key, nonce, tag, ciphertext = \
           [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
        file_in.close()

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        plaintext = data

    with open(file_path + f'_{mode}.txt', 'wb') as encrypted_file:
        file= file_path + f'_{mode}.txt'
        encrypted_file.write(plaintext)
    show_feedback("File was successfully decrypted")


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
    global shift_entry
    shift_entry = tk.Entry(caesar_window)
    shift_entry.pack()
    encrypt_button_caesar = tk.Button(caesar_window, text="Datei verschlüsseln (Caesar)", command=lambda: encrypt_file('Caesar'))
    decrypt_button_caesar = tk.Button(caesar_window, text="Datei entschlüsseln (Caesar)", command=lambda: decrypt_file('Caesar'))
    encrypt_button_caesar.pack()
    decrypt_button_caesar.pack()

def open_asymmetric_window():
    asym_window = tk.Toplevel(root)
    asym_window.title("Asymmetrische Verschlüsselung/Entschlüsselung")
    KeyGen_button_AS= tk.Button(asym_window, text= "Generat key Pair", command= lambda: generat_key('AS'))
    encrypt_button_AS= tk.Button(asym_window, text= "Datei verschlüsseln (AEAD)", command= lambda: encrypt_file('AS'))
    decrypt_button_AS= tk.Button(asym_window, text= "Datei entschlüsseln (AEAD)", command= lambda: decrypt_file('AS'))
    KeyGen_button_AS.pack() 
    encrypt_button_AS.pack()
    decrypt_button_AS.pack()
    

def show_feedback(message):
    label = tk.Label(root, text=message, padx=20, pady=20)
    label.pack()

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
