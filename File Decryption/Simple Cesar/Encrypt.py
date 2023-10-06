def encrypt_text(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted_char = chr(((ord(char) - ord('a' if char.islower() else 'A') + shift) % 26) + ord('a' if char.islower() else 'A'))
            encrypted_text += shifted_char
        else:
            encrypted_text += char
    return encrypted_text

try:
    # Open the file in read mode
    with open('Date.txt', 'r') as file:
        # Read the contents
        content = file.read()

        # Get the shift value from the user
        shift = int(input("Enter the number of letters to shift: "))

        # Encrypt the content with the specified shift
        modified_content = encrypt_text(content, shift)

    # Write the modified content to a new file
    with open('ModifiedData.txt', 'w') as output_file:
        output_file.write(modified_content)

    print("File 'Data.txt' successfully modified and saved as 'ModifiedData.txt'.")
except FileNotFoundError:
    print("File 'Data.txt' not found.")
except Exception as e:
    print("An error occurred:", e)
