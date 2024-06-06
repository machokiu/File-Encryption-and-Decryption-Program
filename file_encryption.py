'''
@author Marci Ma
File encryption Utility
'''

import os
import hashlib
import hmac
from pbkdf2 import pbkdf2 #key_generation 
from Crypto.Cipher import AES, DES3 # encryption
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes # IV generation
import json # output file format

# Supported encryption algorithms
# AES128:16bytes, AES256:32bytes, 3DES:24bytes

ENCRYPTION_ALGORITHMS = {'AES128', 'AES256', '3DES'}

# Supported hashing algorithms
HASHING_ALGORITHMS = {'SHA256', 'SHA512'} 

# generate a master key
# using different hashlib depends on the hashing_algorithm
def generate_master_key(password, salt, hashing_algorithm, iteration):
    if hashing_algorithm == 'SHA256':
        master_key = pbkdf2(hashlib.sha256, password, salt, iteration, 32)
    elif hashing_algorithm == 'SHA512':
        master_key = pbkdf2(hashlib.sha512, password, salt, iteration, 64) # 64bytes key for the SHA512
    
    return master_key

# generate an encryption key and HMAC key
def generate_derive_key(master_key,hashing_algorithm):
    # check the hashing algorithm to determine the hashing module
    # The largest key size of the encryption algorithm is 32 bytes, so the key is set to be 32 bytes
    
    if hashing_algorithm == 'SHA256':
        encryption_key = pbkdf2(hashlib.sha256, master_key, b'ENCRYPTION_SALT', 1, 32)  # Fixed salt, 1 iteration
        HMAC_key = pbkdf2(hashlib.sha256, master_key, b'HMAC_SALT', 1, 32)  # Fixed salt, 1 iteration
    
    elif hashing_algorithm == 'SHA512':
        encryption_key = pbkdf2(hashlib.sha512, master_key, b'ENCRYPTION_SALT', 1, 32)
        HMAC_key = pbkdf2(hashlib.sha512, master_key, b'HMAC_SALT', 1, 32)
    
    return encryption_key, HMAC_key

# encrypt your data with Ke and IV
# depending the encryption algorithm, the cipher suite is different
def encrypt_data(data, encryption_key, IV, encryption_algorithm):
    if encryption_algorithm == 'AES128':
        cipher = AES.new(encryption_key[:16], AES.MODE_CBC, IV) # key size is 16 bytes
    elif encryption_algorithm == 'AES256':
        cipher = AES.new(encryption_key, AES.MODE_CBC, IV) #key size is 32 bytes
    elif encryption_algorithm == '3DES':
        cipher = DES3.new(encryption_key[:24], DES3.MODE_CBC, IV) # key size is 21 bytes, but block size usually is 8 bytes, so used 24 bytes

    padded_data = pad(data, cipher.block_size) # padding is neccessary for different block size
    encrypted_data = cipher.encrypt(padded_data)
    
    return encrypted_data

# decrypt the data
# same approach as encrypting the data in reverse order
def decrypt_data(encrypted_data, encryption_key, IV, encryption_algorithm):
    if encryption_algorithm == 'AES128':
        cipher = AES.new(encryption_key[:16], AES.MODE_CBC, IV)
    elif encryption_algorithm == 'AES256':
        cipher = AES.new(encryption_key, AES.MODE_CBC, IV)
    elif encryption_algorithm == '3DES':
        cipher = DES3.new(encryption_key[:24], DES3.MODE_CBC, IV)
    
    decrypted_data = cipher.decrypt(encrypted_data)
    unpadded_data = unpad(decrypted_data, cipher.block_size) # unpadding the data to cut out all the random bytes in front or behind the actual data
    
    return unpadded_data

# create an HMAC with Kh, covering both IV and encrypted data
# included the hashing algorithm to ensure HMAC is corresponding to the user's choice of hashing
def create_HMAC(encrypted_data, HMAC_key, IV, hashing_algorithm):
    if hashing_algorithm == 'SHA256':
        
        # use the HMAC_key and generate HMAC value cover IV+encrypted_data
        data_to_HMAC = IV + encrypted_data
        HMAC_value = hmac.new(HMAC_key, data_to_HMAC, hashlib.sha256)
        
    elif hashing_algorithm == 'SHA512':
        data_to_HMAC = IV + encrypted_data
        HMAC_value = hmac.new(HMAC_key, data_to_HMAC, hashlib.sha512) 
    
    return HMAC_value.digest()


# This is the main function to call the corresponding helper function in order
# 1. generate random value for salt and decide the iteration
# 2. generate the master key
# 3. key derive for encryption key and HMAC key
# 4. generate IV for one block size
# 5. encrypt the data
# 6. generate the HMAC
# 7. write all the data to the json file

def encrypt_file(input_file, password, encryption_algorithm, hashing_algorithm):
    
    with open(input_file, 'rb') as f: # open the file and read in binary
        data = f.read()
    
    salt = os.urandom(16)   # generate 16 bits random strings
    
    #iteration = 2000000 
    #iteration = 1000000
    #iteration = 600000
    '''I have tested the encryption with various iteration counts. While more iterations increase the security level, they also impact performance. For instance, 2,000,000 iterations took more than 3 seconds to complete the encryption. Reducing the iterations to half still took 1-2 seconds. If the file to be encrypted is large, the time required will be even longer. Therefore, I believe 400,000 iterations is a reasonable value that balances performance and security.
    '''
    iteration = 400000 
    
    master_key = generate_master_key(password.encode('utf-8'), salt, hashing_algorithm, iteration) # password string need to convert to bytes
    encryption_key, HMAC_key = generate_derive_key(master_key, hashing_algorithm)
    
    if encryption_algorithm == '3DES': #different block size, IV can only be 8 bytes for 3DES
        IV = get_random_bytes(8)
    else:
        IV = get_random_bytes(16) # AES-encryption 16 bytes
        
    encrypted_data = encrypt_data(data, encryption_key, IV, encryption_algorithm)
    hmac_value = create_HMAC(encrypted_data, HMAC_key, IV, hashing_algorithm)
        
    output_filename = input_file + '.enc' # output file has an extra extension
    
    # convert data to HEX to increase human readibility and lower the chance of large file size
    metadata = {
        'Master_Key_Salt': salt.hex(),
        'IV': IV.hex(),
        'Hashing_Algorithm': hashing_algorithm,
        'Encryption_Algorithm': encryption_algorithm,
        'Iteration': iteration,
        'HMAC': hmac_value.hex(),
        'Encrypted_data': encrypted_data.hex()
    }
    
    with open(output_filename, 'w') as json_file:
        json.dump(metadata, json_file)
    
    return output_filename    

# read the file for decryption
# only decrypt the file with the .enc extension
# compare the HMAC value to ensure the data integrity
def decrypt_file(input_file, password):
    
    with open(input_file, 'r') as f:
        metadata = json.load(f)

    # convert back to bytes before processing any decryption
    salt = bytes.fromhex(metadata['Master_Key_Salt'])
    IV = bytes.fromhex(metadata['IV'])
    hashing_algorithm = metadata['Hashing_Algorithm']
    encryption_algorithm = metadata['Encryption_Algorithm']
    iteration = metadata['Iteration']
    hmac_value = bytes.fromhex(metadata['HMAC'])
    encrypted_data = bytes.fromhex(metadata['Encrypted_data'])

    master_key = generate_master_key(password.encode('utf-8'), salt, hashing_algorithm, iteration)
    encryption_key, hmac_key = generate_derive_key(master_key, hashing_algorithm)

    # error handling for the HMAC tampering
    if(create_HMAC(encrypted_data, hmac_key, IV, hashing_algorithm) != hmac_value):
        raise ValueError('HMAC verification failed. File may be tampered.')

    decrypted_data = decrypt_data(encrypted_data, encryption_key, IV, encryption_algorithm)
    output_file = os.path.splitext(input_file)[0] # the output_file would be the same as the original file, it wouldn't generate a new file
    
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)
        
    return output_file

def main():
    
    # File Encryption Utility Description
    print(""" Welcome to the File Encryption Utility! This tool allows you to encrypt and decrypt your files to keep them safe and secure.
          How it works:

        1. Encrypt: Choose the "encrypt" mode to encrypt your files. You'll be prompted to enter the file you want to encrypt, along with a password. Your file will be encrypted with your chosen settings, making it unreadable to anyone without the password.

        2. Decrypt: Choose the "decrypt" mode to decrypt previously encrypted files. You'll need to provide the encrypted file and the password used for encryption. The utility will verify the password and decrypt the file, restoring it to its original state.

        Remember: Keep your password secure and do not forget it. Without the correct password, you won't be able to decrypt your files! """)

    while True:
        # user pick the mode at the start
        mode = input('Do you want to encrypt or decrypt a file? (encrypt/decrypt/exit): ').lower()
        
        if mode == 'encrypt':
            
            input_file = input('Enter the path of the file to encrypt: ')
            # Check if the file exists
            if not os.path.exists(input_file):
                print('Error: File not found.')
                continue
            
            password = input('Enter the password: ')
            
            encryption_algorithm = input('Enter the encryption algorithm (AES128/AES256/3DES): ').upper()
            # Check if the encryption algorithm is supported
            if encryption_algorithm not in ENCRYPTION_ALGORITHMS:
                print("Error: Invalid encryption algorithm.")
                continue
            
            hashing_algorithm = input('Enter the hashing algorithm (SHA256/SHA512): ').upper()    
            # Check if the hashing algorithm is supported
            if hashing_algorithm not in HASHING_ALGORITHMS:
                print('Error: Invalid hashing algorithm.')
                continue
                
            # Perform encryption
            try:
                encrypted_file = encrypt_file(input_file, password, encryption_algorithm, hashing_algorithm)
                print(f'File encrypted successfully: {encrypted_file}')
                pass
            except Exception as e:
                print('Encryption failed:', str(e))
            
        elif mode == 'decrypt':
            input_file = input('Enter the path of the file to decrypt: ')
            password = input('Enter the password: ')
            
            # Check if the file exists
            if not os.path.exists(input_file):
                print('Error: File not found.')
                continue
                
            # Check if the file has the .enc extension
            if not input_file.endswith('.enc'):
                print('Error: Input file must have the .enc extension.')
                continue
                
            # Perform decryption
            try:
                decrypted_file = decrypt_file(input_file, password)
                print(f'File decrypted successfully: {decrypted_file}')
                pass
            except Exception as e:
                print('Decryption failed:', str(e))
        
        # exiting the program if user want to exit    
        elif mode == 'exit':
            print('Exiting the program.')
            break
            
        else:
            print('Error: Invalid mode. Please enter (encrypt/decrypt/exit): ')
            continue
        
        # Ask the user if they want to perform another action
        repeat = input('Do you want to perform another action? (yes/no): ').lower()
        if repeat != 'yes':
            break

if __name__ == "__main__":
    main()