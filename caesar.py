def caesar_cipher(text, shift):
    result = ""
    shift = int(shift)  # Stelle sicher, dass shift eine Ganzzahl ist
    for char in text:
        if char.isalpha():
            is_lower = char.islower()
            base = ord('a' if is_lower else 'A')
            shifted_char = chr(((ord(char) - base + shift) % 26) + base)
        else:
            shifted_char = char
        result += shifted_char
    return result



def caesar_decipher(text, shift):
    return caesar_cipher(text, -int(shift))
