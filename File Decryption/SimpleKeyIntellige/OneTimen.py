import pdb;
def XOR(word1, word2):
    xorWord =[chr(ord(a) ^ ord(b)) for a, b in zip(word1, word2)]
    xorWord = ''.join(xorWord)



    return xorWord
def encrypt(message, key):
    # Initialize an index to keep track of where we are in the key
    key_index = 0
    
    # IV Vector as a string
    iv = "10110101001100110110010011110111010010010100111110101111001111001101001100100111011010"
    iv_used = 42
    block_size = len(key)
    # Initialize a list to store the decrypted blocks
    encrypted_blocks = [key[i:i+block_size] for i in range(0, len(message), block_size)]
    
    # Split the message into blocks of the key length
    
    message_blocks = [message[i:i+block_size] for i in range(0, len(message), block_size)]

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
                            
            blocksec_list = [chr(ord(block_char) ^ ord(key_char)) for block_char, key_char in zip(block, key)]
            blocksec_list = ''.join(blocksec_list)
            blockcipherPart = [chr(ord(Blocksec_list_char) ^ ord(encrypted_char)) for Blocksec_list_char ,encrypted_char in zip(blocksec_list, encrypted_blocks[key_index-1])]
            blocksec = ''.join(blockcipherPart)
            pdb.set_trace()
            encrypted_blocks[key_index] = blocksec
            key_index = key_index + 1
        

    # Join the message_blocks into a single string
    message_combined = ''.join(encrypted_blocks)

    # Return the combined message
    return message_combined

try:
    # Read the message from Data.txt
    with open('Data.txt', 'r') as message_file:
        message = message_file.read()

    # Read the key from Key.txt
    with open('Key.txt', 'r') as key_file:
        key = key_file.read()
        
    with open('KeyDoppel.txt', 'r') as key_file:
        keyDoppel = key_file.read()

    # XOR the message with the modified key
    modified_message = encrypt(message, key)

    # Save the modified message in ModifiedData.txt
    with open('ModifiedData.txt', 'w') as output_file:
        output_file.write(modified_message)

    print("Message XORed and saved as 'ModifiedData.txt'.")
except FileNotFoundError:
    print("File 'Data.txt' or 'Key.txt' not found.")
except Exception as e:
    print("An error occurred:", e)

