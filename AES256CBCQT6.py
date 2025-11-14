#AES_256_CBC加密, 随机化初始向量IV
#未添加注释,为了代码的简洁性^_^
import os
import sys
import hashlib
import secrets
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from PySide6.QtWidgets import QApplication, QMainWindow, QFileDialog
from ui import Ui_mainwindow
AES_KEY_SIZE = 32
AES_BLOCK_SIZE = 16
def str_to_sha256(text: str) -> str:
    if not text:
        return ""
    sha256_hash = hashlib.sha256(text.encode('utf-8')).hexdigest()
    return sha256_hash
def generate_iv() -> bytes:
    return os.urandom(AES_BLOCK_SIZE)
def hex_to_bytes(hex_string: str) -> bytes:
    try:
        return bytes.fromhex(hex_string)
    except ValueError:
        return b''
def bytes_to_hex(data: bytes) -> str:
    return data.hex()
def encrypt_file(input_path: str, key: bytes, output_path: str = None) -> bool:
    try:
        if len(key) != AES_KEY_SIZE:
            return False
        iv = generate_iv()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(AES_BLOCK_SIZE * 8).padder()
        with open(input_path, "rb") as f_in:
            plaintext = f_in.read()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        if output_path is None:
            output_path = input_path
        with open(output_path, "wb") as f_out:
            f_out.write(iv)
            f_out.write(ciphertext)
        return True
    except Exception as e:
        print(f"Encryption failed: {str(e)}")
        return False
def decrypt_file(input_path: str, key: bytes, output_path: str = None) -> bool:
    try:
        if len(key) != AES_KEY_SIZE:
            return False
        with open(input_path, "rb") as f_in:
            iv = f_in.read(AES_BLOCK_SIZE)
            ciphertext = f_in.read()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(AES_BLOCK_SIZE * 8).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        if output_path is None:
            output_path = input_path
        with open(output_path, "wb") as f_out:
            f_out.write(plaintext)
        return True
    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        return False
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_mainwindow()
        self.ui.setupUi(self)
        self.connect_signals()
        self.log_message("Initialization successful", "info")
    def log_message(self, message: str, message_type: str = "info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        if message_type == "error":
            prefix = "[ERROR]"
        elif message_type == "warning":
            prefix = "[WARNING]"
        elif message_type == "success":
            prefix = "[SUCCESS]"
        else:
            prefix = "[INFO]"
        formatted_message = f"[{timestamp}] {prefix} {message}"
        self.ui.messagedisplay.appendPlainText(formatted_message)
        scrollbar = self.ui.messagedisplay.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    def connect_signals(self):
        self.ui.browsebutton_en.clicked.connect(self.browse_file_encrypt)
        self.ui.browsebutton_en_output.clicked.connect(self.browse_output_file_encrypt)
        self.ui.randomkeybutton_en.clicked.connect(self.generate_random_key)
        self.ui.paste_password_en.clicked.connect(lambda: self.paste_text(self.ui.passwordline_en))
        self.ui.encrypt.clicked.connect(self.encrypt_file_gui)

        # 解密页面
        self.ui.browsebutton_de.clicked.connect(self.browse_file_decrypt)
        self.ui.browsebutton_de_output.clicked.connect(self.browse_output_file_decrypt)
        self.ui.paste_password_de.clicked.connect(lambda: self.paste_text(self.ui.passwordline_de))
        self.ui.paste_hex_de.clicked.connect(lambda: self.paste_text(self.ui.keyhexline_de))
        self.ui.decrypt.clicked.connect(self.decrypt_file_gui)

        # 实时密码转SHA256
        self.ui.passwordline_en.textChanged.connect(self.update_sha256_hex_en)
        self.ui.passwordline_de.textChanged.connect(self.update_sha256_hex_de)

    def update_sha256_hex_en(self):
        password = self.ui.passwordline_en.text()
        sha256_hex = str_to_sha256(password)
        self.ui.keyhexline_en.setText(sha256_hex)
    def update_sha256_hex_de(self):
        password = self.ui.passwordline_de.text()
        sha256_hex = str_to_sha256(password)
        self.ui.keyhexline_de.setText(sha256_hex)
    def browse_file_encrypt(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Choose file for encrypt", "", "*"
        )
        if file_path:
            self.ui.filepathline_en.setText(file_path)
    def browse_output_file_encrypt(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Choose file for save", "", "*"
        )
        if file_path:
            self.ui.outputline_en.setText(file_path)
    def browse_file_decrypt(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Choose file for decrypt", "", "*"
        )
        if file_path:
            self.ui.filepathline_de.setText(file_path)
    def browse_output_file_decrypt(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Choose file for save", "", "*"
        )
        if file_path:
            self.ui.outputline_de.setText(file_path)
    def paste_text(self, target_lineedit):
        clipboard = QApplication.clipboard()
        text = clipboard.text()
        if text:
            target_lineedit.setText(text)
            self.log_message(f"Pasted into the input box", "info")
    def generate_random_key(self):
        random_key = secrets.token_hex(32)
        self.ui.keyhexline_en.setText(random_key)
        self.log_message("A random key has been generated", "info")
    def is_valid_file_path(self, path: str) -> bool:
        if not path or not path.strip():
            return False
        try:
            directory = os.path.dirname(path)
            if directory and not os.path.exists(directory):
                return False
            return True
        except Exception as e:
            self.log_message(f"Output path is invalid:{str(e)}", "warning")
            return False
    def encrypt_file_gui(self):
        input_path = self.ui.filepathline_en.text()
        output_path = self.ui.outputline_en.text().strip()  # 去除前后空格
        key_hex = self.ui.keyhexline_en.text()
        if not input_path:
            self.log_message("Please select the file to encrypt", "warning")
            return
        if not os.path.exists(input_path):
            self.log_message(f"File does not exist: {input_path}", "error")
            return
        if not key_hex:
            self.log_message("Password or key is required", "warning")
            return
        key_bytes = hex_to_bytes(key_hex)
        if len(key_bytes) != AES_KEY_SIZE:
            self.log_message(f"The key is invalid and should be 64 hexadecimal characters.", "error")
            return
        final_output_path = None
        if output_path and self.is_valid_file_path(output_path):
            final_output_path = output_path
            operation_type = "Encrypting file and saving to output path"
        else:
            operation_type = "Encrypting file"
            if output_path:
                self.ui.outputline_en.clear()
                self.log_message("Output path is invalid, will encrypt the original file", "warning")
        try:
            self.log_message(f"Start {operation_type}: {os.path.basename(input_path)}", "info")
            success = encrypt_file(input_path, key_bytes, final_output_path)
            if success:
                if final_output_path:
                    self.log_message(
                        f"File encrypted successfully: {os.path.basename(input_path)} ---> {os.path.basename(final_output_path)}",
                        "success")
                else:
                    self.log_message(f"File encrypted successfully: {os.path.basename(input_path)} (original file encrypted)", "success")
                # 清空密码
                self.ui.passwordline_en.clear()
            else:
                self.log_message("File encryption failed!", "error")
        except Exception as e:
            self.log_message(f"Error occurred during encryption: {str(e)}", "error")
    def decrypt_file_gui(self):
        input_path = self.ui.filepathline_de.text()
        output_path = self.ui.outputline_de.text().strip()  # 去除前后空格
        key_hex = self.ui.keyhexline_de.text()
        if not input_path:
            self.log_message("Please select the file to decrypt", "warning")
            return
        if not os.path.exists(input_path):
            self.log_message(f"File does not exist: {input_path}", "error")
            return
        if not key_hex:
            self.log_message("Please enter key or password", "warning")
            return
        key_bytes = hex_to_bytes(key_hex)
        if len(key_bytes) != AES_KEY_SIZE:
            self.log_message(f"The key is invalid and should be 64 hexadecimal characters.", "error")
            return
        final_output_path = None
        if output_path and self.is_valid_file_path(output_path):
            final_output_path = output_path
            operation_type = "Decrypting to new file"
        else:
            operation_type = "Decrypting original file"
            if output_path:
                self.ui.outputline_de.clear()
                self.log_message("Output path is invalid, will decrypt the original file", "warning")
        try:
            self.log_message(f"Start {operation_type}: {os.path.basename(input_path)}", "info")
            success = decrypt_file(input_path, key_bytes, final_output_path)
            if success:
                if final_output_path:
                    self.log_message(
                        f"File decrypted successfully: {os.path.basename(input_path)} → {os.path.basename(final_output_path)}",
                        "success")
                else:
                    self.log_message(f"File decrypted successfully: {os.path.basename(input_path)} (original file decrypted)", "success")
                self.ui.passwordline_de.clear()
            else:
                self.log_message("File decryption failed! Please check if the key is correct or the file is damaged.", "error")
        except Exception as e:
            self.log_message(f"Error occurred during decryption: {str(e)}", "error")
def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
if __name__ == "__main__":
    main()
