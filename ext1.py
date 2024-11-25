import os
import rsa
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QFileDialog, QInputDialog, QLineEdit
from PyQt6.QtCore import Qt

# Utility to generate a random key for AES encryption
def generate_aes_key():
    return os.urandom(32)  # 256-bit key for AES

# Encrypt using AES
def aes_encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = data + (b' ' * (16 - len(data) % 16))  # Padding data to be block-aligned
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted  # Return IV + encrypted data for decryption

# Encrypt using RSA
def rsa_encrypt(data, public_key):
    return rsa.encrypt(data.encode(), public_key)

# Combine the encryption layers to create an onion-like encryption
def create_onion_encrypted_file(data, file_path, pin):
    # Hash the PIN to generate a secure key
    hashed_pin = hashlib.sha256(pin.encode()).hexdigest()

    # Generate RSA key pair based on the hashed PIN
    public_key, private_key = rsa.newkeys(2048)

    # Save the private key as a .pem file
    private_key_pem = private_key.save_pkcs1()
    private_key_path, _ = QFileDialog.getSaveFileName(None, "Save Private Key", "", "PEM Files (*.pem)")

    if private_key_path:
        with open(private_key_path, "wb") as f:
            f.write(private_key_pem)
        print(f"Private key saved to {private_key_path}")
    else:
        print("Private key not saved.")

    # AES encryption using random key
    aes_key = generate_aes_key()
    encrypted_data = aes_encrypt(data.encode(), aes_key)

    # RSA encryption of AES key
    encrypted_aes_key = rsa_encrypt(aes_key.hex(), public_key)

    # Write encrypted data to file
    with open(file_path, 'wb') as f:
        f.write(encrypted_aes_key)  # Write RSA encrypted AES key
        f.write(encrypted_data)  # Write AES encrypted data

# Decrypt using AES
def aes_decrypt(encrypted_data, key):
    iv = encrypted_data[:16]  # Extract the IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    return decrypted.rstrip(b' ')  # Remove padding

# Decrypt using RSA
def rsa_decrypt(encrypted_data, private_key):
    decrypted = rsa.decrypt(encrypted_data, private_key)
    return decrypted.decode()

# Decrypt the onion-encrypted .xyz file
def decrypt_onion_encrypted_file(file_path, private_key):
    with open(file_path, 'rb') as f:
        encrypted_aes_key = f.read(256)  # Read the RSA-encrypted AES key
        encrypted_data = f.read()  # Read the AES-encrypted data

    aes_key_hex = rsa_decrypt(encrypted_aes_key, private_key)
    aes_key = bytes.fromhex(aes_key_hex)  # Convert the hex string back to bytes

    decrypted_data = aes_decrypt(encrypted_data, aes_key)
    return decrypted_data.decode()

# PyQt6 Application Class
class EncryptionApp(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Onion Encryption Tool")
        self.setGeometry(100, 100, 600, 400)

        self.init_ui()

    def init_ui(self):
        self.layout = QVBoxLayout()

        # Text area to input data
        self.text_input = QTextEdit(self)
        self.text_input.setPlaceholderText("Enter data to encrypt...")
        self.layout.addWidget(self.text_input)

        # Button to create and save the encrypted .xyz file
        self.encrypt_button = QPushButton("Encrypt and Save .xyz File", self)
        self.encrypt_button.clicked.connect(self.encrypt_and_save)
        self.layout.addWidget(self.encrypt_button)

        # Button to decrypt the .xyz file
        self.decrypt_button = QPushButton("Decrypt .xyz File", self)
        self.decrypt_button.clicked.connect(self.decrypt_file)
        self.layout.addWidget(self.decrypt_button)

        # Display decrypted text
        self.decrypted_output = QTextEdit(self)
        self.decrypted_output.setPlaceholderText("Decrypted data will appear here...")
        self.decrypted_output.setReadOnly(True)
        self.layout.addWidget(self.decrypted_output)

        self.setLayout(self.layout)

    def encrypt_and_save(self):
        data = self.text_input.toPlainText()
        if data:
            # Prompt for a 12-digit PIN
            pin, ok = QInputDialog.getText(self, "Enter PIN", "Enter a 12-digit PIN:")

            if ok and len(pin) == 12:
                # Open file dialog to save the file
                file_path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted File", "", "XYZ Files (*.xyz)")

                if file_path:
                    create_onion_encrypted_file(data, file_path, pin)
                    self.text_input.clear()
                    print(f"File saved to {file_path}")
                else:
                    print("No file path selected.")
            else:
                print("Invalid PIN. Please enter a 12-digit PIN.")
        else:
            print("No data to encrypt.")

    def decrypt_file(self):
        # Open file dialog to select the encrypted .xyz file
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Encrypted File", "", "XYZ Files (*.xyz)")

        if file_path:
            # Prompt for the private key to decrypt the file
            private_key_input, _ = QFileDialog.getOpenFileName(self, "Select Private Key File", "", "PEM Files (*.pem)")
            if private_key_input:
                with open(private_key_input, "rb") as f:
                    private_key = rsa.PrivateKey.load_pkcs1(f.read())

                try:
                    decrypted_data = decrypt_onion_encrypted_file(file_path, private_key)
                    self.decrypted_output.setText(decrypted_data)
                except Exception as e:
                    print(f"Error: {e}")
                    self.decrypted_output.setText("Decryption failed.")
            else:
                print("No private key selected.")
        else:
            print("No file selected.")

# Run the application
if __name__ == '__main__':
    app = QApplication([])
    window = EncryptionApp()
    window.show()
    app.exec()
