# File Encryption and Decryption Tool

This Python program allows you to encrypt and decrypt files using various encryption methods. It also provides the functionality to generate public and private keys for RSA encryption. The program uses the Tkinter library for the user interface and the Crypto library for encryption and decryption.

## Table of Contents

1. [Features](#features)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Encryption Methods](#encryption-methods)
5. [Generating RSA Keys](#generating-rsa-keys)
6. [Contributing](#contributing)
7. [License](#license)
8. [Known Problem](#Known-Problem)

## Features<a name="features"></a>

- Encryption and decryption of files using ECB and CBC modes for symmetric encryption.
- Caesar cipher encryption and decryption.
- Asymmetric encryption and decryption using RSA.
- Key generation for RSA encryption.
- User-friendly graphical interface using Tkinter.

## Installation<a name="installation"></a>

To use this program, you'll need to have Python and the required libraries installed. You can install the necessary libraries using pip:

pip install pycryptodome


## Usage

Run the program by executing the script. You will be presented with options to choose an encryption method: ECB, CBC, Caesar, or Asymmetric. Select the desired method, and follow the instructions to encrypt or decrypt a file. For Asymmetric encryption, you can also generate RSA key pairs.

## Encryption Methods

### ECB and CBC

- **ECB (Electronic Codebook):** This method encrypts the file using a symmetric key. You can choose either ECB or CBC mode.
- **CBC (Cipher Block Chaining):** Similar to ECB, but with a different mode for added security.

### Caesar Cipher

Caesar encryption allows you to shift the characters in the file by a specified number of positions.

### Asymmetric Encryption

Asymmetric encryption using RSA allows you to generate a key pair and use the public key to encrypt and the private key to decrypt files.

## Generating RSA Keys

To generate RSA key pairs for asymmetric encryption, choose the "Asymmetric" option from the main menu. Click "Generate Key Pair" to generate the keys. This will create "privateKey.pem" and "publicKey.pem" files.

## Contributing

Feel free to contribute to this project by submitting issues or pull requests on GitHub.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

Enjoy secure file encryption and decryption with this tool! If you have any questions or need further assistance, feel free to reach out.

## Known Problem <a name="Known-Problem"></a>

Issue 1: Windows do not close when finished encrypting or decrypting
Issue 2: Feedback messages are stacked, does not look nice