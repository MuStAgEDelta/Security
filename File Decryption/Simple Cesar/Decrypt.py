def shift_text(text, shift):
    shifted_text = ""
    for char in text:
        if char.isalpha():
            shifted_char = chr(((ord(char) - ord('a' if char.islower() else 'A') + shift) % 26) + ord('a' if char.islower() else 'A'))
            shifted_text += shifted_char
        else:
            shifted_text += char
    return shifted_text

try:
    # Open the file in read mode
    with open('ModifiedData.txt', 'r') as file:
        # Read the contents
        content = file.read()

        # Get the shift value from the user
        shift = int(input("Enter the number of letters to shift (positive for encryption, negative for decryption): "))

        # Encrypt or decrypt the content with the specified shift
        modified_content = shift_text(content, shift)

    # Determine whether we are encrypting or decrypting
    action = "encrypted" if shift > 0 else "decrypted"

    # Write the modified content to a new file
    with open('Decrypt.txt', 'w') as output_file:
        output_file.write(modified_content)

    print(f"File 'Data.txt' successfully {action} and saved as 'Decrypt.txt'.")
except FileNotFoundError:
    print("File 'Data.txt' not found.")
except Exception as e:
    print("An error occurred:", e)
