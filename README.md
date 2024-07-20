# File-Encryption-and-Decryption-Program
This Python program provides a comprehensive solution for securely encrypting and decrypting files using popular cryptographic algorithms. It supports AES128, AES256, and 3DES encryption algorithms and offers SHA256 and SHA512 for hashing. The program ensures data integrity by creating an HMAC for each file.

# Features
- Encryption Algorithms: AES128, AES256, and 3DES
- Hashing Algorithms: SHA256 and SHA512
- Key Derivation: PBKDF2 with customizable iterations for generating strong encryption keys
- Data Integrity: HMAC creation to verify the integrity of encrypted data
- Metadata Storage: JSON format for storing encryption details

# Usage
- Encryption: The user is prompted to enter the file path, password, encryption algorithm, and hashing algorithm. The file is encrypted, and a metadata file is generated.
- Decryption: The user is prompted to enter the encrypted file path and password. The file is decrypted using the information from the metadata file.

# Functions
## generate_master_key
- Purpose: Generates a master key from a password using PBKDF2 with the specified hashing algorithm and iteration count.
- Parameters: password (string), salt (bytes), hashing_algorithm (string), iteration (int)
- Returns: Master key (bytes)

## generate_derive_key
- Purpose: Derives an encryption key and an HMAC key from the master key using the specified hashing algorithm.
- Parameters: master_key (bytes), hashing_algorithm (string)
- Returns: Tuple containing encryption key (bytes) and HMAC key (bytes)

## encrypt_data
- Purpose: Encrypts data using the specified encryption key, IV, and encryption algorithm.
- Parameters: data (bytes), encryption_key (bytes), IV (bytes), encryption_algorithm (string)
- Returns: Encrypted data (bytes)

## decrypt_data
- Purpose: Decrypts data using the specified encryption key, IV, and encryption algorithm.
- Parameters: encrypted_data (bytes), encryption_key (bytes), IV (bytes), encryption_algorithm (string)
- Returns: Decrypted data (bytes)

## create_HMAC
- Purpose: Creates an HMAC for the encrypted data and IV using the specified HMAC key and hashing algorithm.
- Parameters: encrypted_data (bytes), HMAC_key (bytes), IV (bytes), hashing_algorithm (string)
- Returns: HMAC value (bytes)

## encrypt_file
- Purpose: Encrypts a file and stores the metadata, including encryption details and HMAC, in a JSON file.
- Parameters: input_file (string), password (string), encryption_algorithm (string), hashing_algorithm (string)
- Returns: Path to the encrypted file (string)

## decrypt_file
- Purpose: Decrypt a file using the metadata stored in the JSON file and the provided password.
- Parameters: input_file (string), password (string)
- Returns: Path to the decrypted file (string)

## main()
- Purpose: Provides a user interface for selecting encryption or decryption mode, inputting necessary parameters, and executing the corresponding functions.
- Behavior: Prompts the user to enter 'encrypt' or 'decrypt', then guides through the required steps based on the chosen mode.

