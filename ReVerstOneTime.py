import pdb
def xor_text(ciphertext, key):
    # Ensure the key is repeated to match the length of the ciphertext
    pdb.set_trace()
    key = key * (len(ciphertext) // len(key)) + key[:len(ciphertext) % len(key)]
    # XOR the ciphertext and key character by character
    result = [chr(ord(ciphertext_char) ^ ord(key_char)) for ciphertext_char, key_char in zip(ciphertext, key)]
    
    return ''.join(result)

