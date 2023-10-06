import pdb;
def XOR(word1, word2):
    xorWord =[chr(ord(a) ^ ord(b)) for a, b in zip(word1, word2)]
    xorWord = ''.join(xorWord)



    return xorWord
def decrypt(message, key):
    # Initialize an index to keep track of where we are in the key
    
    
    # IV Vector as a string
    iv = "10110101001100110110010011110111010010010100111110101111001111001101001100100111011010"
    iv_used = 42
    block_size = len(key)
    # Initialize a list to store the decrypted blocks
    encrypted_blocks = [key[i:i+block_size] for i in range(0, len(message), block_size)]
    
    # Split the message into blocks of the key length
    
    message_blocks = [message[i:i+block_size] for i in range(0, len(message), block_size)]
    key_index = 0
    for block in message_blocks:
        # Add IV Vector
        if iv_used != 0:
            WertIV = XOR(block,iv)
            cipherPart=XOR(WertIV,key)
            iv_used = 0
            pdb.set_trace()
            encrypted_blocks[key_index] = cipherPart
            key_index = key_index + 1
        
        else:
            blockkey = XOR(block,key)
            blocksec = XOR(blockkey,encrypted_blocks[key_index-1])
            
            pdb.set_trace()
            encrypted_blocks[key_index] = blocksec
            key_index = key_index + 1
        

    # Join the message_blocks into a single string
    message_combined = ''.join(encrypted_blocks)

    # Return the combined message
    return message_combined

try:
    # Read the modified data from ModifiedData.txt
    with open('ModifiedData.txt', 'r') as ciphertext_file:
        ciphertext = ciphertext_file.read()

    # Read the key from Key.txt
    with open('Key.txt', 'r') as key_file:
        key = key_file.read()
        
    with open('KeyDoppel.txt', 'r') as key_file:
        keyDoppel = key_file.read()

    # Decrypt the modified data with the modified key
    decrypted_message = decrypt(ciphertext, key)

    # Save the decrypted message in Decrypt.txt
    with open('Decrypt.txt', 'w') as output_file:
        output_file.write(decrypted_message)

    print("Message decrypted and saved as 'Decrypt.txt'.")
except FileNotFoundError:
    print("File 'ModifiedData.txt' or 'Key.txt' not found.")
except Exception as e:
    print("An error occurred:", e)
