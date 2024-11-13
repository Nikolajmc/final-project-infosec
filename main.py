from Crypto.Cipher import AES
import base64

def pad(data):
    """Pads the input data to a multiple of 16 bytes for AES block size."""
    padding_length = 16 - len(data) % 16
    return data + chr(padding_length) * padding_length

def unpad(data):
    """Removes padding from the input data."""
    padding_length = ord(data[-1])
    return data[:-padding_length]

def encrypt(key, raw_data):
    raw_data = pad(raw_data)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    encrypted_bytes = cipher.encrypt(raw_data.encode('utf-8'))
    encrypted_base64 = base64.b64encode(encrypted_bytes).decode('utf-8')
    return encrypted_base64

def decrypt(key, encrypted_data):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(base64.b64decode(encrypted_data))
    decrypted_text = unpad(decrypted_bytes.decode('utf-8'))
    return decrypted_text

if __name__ == "__main__":
    # Example usage
    key = "thisisaverysecurekey1234"
    sensitive_message = "Caesar Cipher"
    
    print("Original Message:", sensitive_message)
    
    # Encrypt the message
    encrypted_message = encrypt(key, sensitive_message)
    print("Encrypted Message:", encrypted_message)
    
    # Decrypt the message
    decrypted_message = decrypt(key, encrypted_message)
    print("Decrypted Message:", decrypted_message)