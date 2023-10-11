def shift_text(filePath, shift):
    shifted_text = ""
    for char in text:
        if char.isalpha():
            shifted_char = chr(((ord(char) - ord('a' if char.islower() else 'A') + shift) % 26) + ord('a' if char.islower() else 'A'))
            shifted_text += shifted_char
        else:
            shifted_text += char
    return shifted_text