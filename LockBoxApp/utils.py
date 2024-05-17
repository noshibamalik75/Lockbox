from cryptography.fernet import Fernet

# Placeholder for Fernet key, you should generate and store this securely
fernet_key = Fernet.generate_key()
cipher_suite = Fernet(fernet_key)

def encrypt_file(file):
    # Encrypt the file and return the path
    encrypted_data = cipher_suite.encrypt(file.read())
    file_path = '../files'
    with open(file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)
    return file_path, encrypted_data

def decrypt_file(file_path):
    # Decrypt the file and return the path
    with open(file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    decrypted_file_path = 'path/to/decrypted/file'
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)
    return decrypted_file_path

def generate_access_key():
    # Generate a secure random access key
    return Fernet.generate_key()