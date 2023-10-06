def xor_text(message, key):
    # Ensure the key is repeated to match the length of the message
    #one flaw, because I can repeat this with a really big message, so I can find the length of the key
    #Todo Fix length error, could use a Hash function on the second and theered part 
    key = key * (len(message) // len(key)) + key[:len(message) % len(key)]
    
    # XOR the message and key character by character
    result = [chr(ord(message_char) ^ ord(key_char)) for message_char, key_char in zip(message, key)]
    
    return ''.join(result)

try:
    # Read the message from Data.txt
    with open('Date.txt', 'r') as message_file:
        message = message_file.read()

    # Read the key from Key.txt
    with open('Key.txt', 'r') as key_file:
        key = key_file.read()

    # XOR the message with the key
    modified_message = xor_text(message, key)

    # Save the modified message in ModifiedData.txt
    with open('ModifiedData.txt', 'w') as output_file:
        output_file.write(modified_message)

    print("Message XORed and saved as 'ModifiedData.txt'.")
except FileNotFoundError:
    print("File 'Data.txt' or 'Key.txt' not found.")
except Exception as e:
    print("An error occurred:", e)
