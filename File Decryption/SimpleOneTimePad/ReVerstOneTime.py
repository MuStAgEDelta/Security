def xor_text(ciphertext, key):
    # Ensure the key is repeated to match the length of the ciphertext
    key = key * (len(ciphertext) // len(key)) + key[:len(ciphertext) % len(key)]
    
    # XOR the ciphertext and key character by character
    result = [chr(ord(ciphertext_char) ^ ord(key_char)) for ciphertext_char, key_char in zip(ciphertext, key)]
    
    return ''.join(result)

try:
    # Read the modified data from ModifiedData.txt
    with open('ModifiedData.txt', 'r') as ciphertext_file:
        ciphertext = ciphertext_file.read()

    # Read the key from Key.txt
    with open('Key.txt', 'r') as key_file:
        key = key_file.read()

    # XOR the modified data with the key to decrypt
    decrypted_message = xor_text(ciphertext, key)

    # Save the decrypted message in Decrypt.txt
    with open('Decrypt.txt', 'w') as output_file:
        output_file.write(decrypted_message)

    print("Message decrypted and saved as 'Decrypt.txt'.")
except FileNotFoundError:
    print("File 'ModifiedData.txt' or 'Key.txt' not found.")
except Exception as e:
    print("An error occurred:", e)
