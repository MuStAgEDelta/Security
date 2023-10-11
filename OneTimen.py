import pdb
def xor_text(message, key):
    # Ensure the key is repeated to match the length of the message
    #one flaw, because I can repeat this with a really big message, so I can find the length of the key
    #Todo Fix length error, could use a Hash function on the second and theered part 
    
    key = key * (len(message) // len(key)) + key[:len(message) % len(key)]
    
    # XOR the message and key character by character
    result = XOR(key,message.encode)
    
    return ''.join(result)


def XOR(word1, word2):
    xorWord =[chr(ord(a) ^ ord(b)) for a, b in zip(word1, word2)]
    xorWord = ''.join(xorWord)



    return xorWord