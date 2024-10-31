import sys
import sqlite3
import secrets
from Crypto.Cipher import AES
import hashlib
from PyQt5 import QtWidgets, QtCore, QtGui
import getpass

class PasswordManager:
    def __init__(self, db_path="passwords.db"):
        self.db_path = db_path
        self.salt = None
        self.key = None
        self.iterations = 500000
    
    def generate_key(self, master_password):
        if not self.salt:
            self.salt = secrets.token_bytes(32)
        return hashlib.pbkdf2_hmac('sha256', master_password.encode(), self.salt, self.iterations)
    
    def encrypt_password(self, password):
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(password.encode())
        return cipher.nonce, tag, ciphertext
    
    def decrypt_password(self, nonce, tag, ciphertext):
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    
    def create_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                              (id INTEGER PRIMARY KEY, website TEXT NOT NULL,
                               username TEXT NOT NULL, nonce BLOB NOT NULL,
                               tag BLOB NOT NULL, ciphertext BLOB NOT NULL)''')
            cursor.execute('''CREATE TABLE IF NOT EXISTS metadata
                              (id INTEGER PRIMARY KEY, salt BLOB NOT NULL)''')
            conn.commit()

    def initialize(self, master_password):
        self.create_db()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT salt FROM metadata LIMIT 1")
            result = cursor.fetchone()
            if result:
                self.salt = result[0]
            else:
                self.salt = secrets.token_bytes(32)
                cursor.execute("INSERT INTO metadata (salt) VALUES (?)", (self.salt,))
                conn.commit()
            self.key = self.generate_key(master_password)

    def save_password(self, website, username, password):
        nonce, tag, ciphertext = self.encrypt_password(password)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO passwords (website, username, nonce, tag, ciphertext) VALUES (?, ?, ?, ?, ?)",
                           (website, username, nonce, tag, ciphertext))
            conn.commit()

    def view_passwords(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT website, username, nonce, tag, ciphertext FROM passwords")
            rows = cursor.fetchall()
            decrypted_passwords = []
            for row in rows:
                website, username, nonce, tag, ciphertext = row
                password = self.decrypt_password(nonce, tag, ciphertext)
                decrypted_passwords.append((website, username, password))
            return decrypted_passwords


class MainWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.pm = PasswordManager()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Sicherer Passwort-Manager")
        self.setGeometry(100, 100, 600, 400)

        self.master_password_label = QtWidgets.QLabel("Master-Passwort:")
        self.master_password_input = QtWidgets.QLineEdit()
        self.master_password_input.setEchoMode(QtWidgets.QLineEdit.Password)

        self.initialize_button = QtWidgets.QPushButton("Initialisieren")
        self.initialize_button.clicked.connect(self.initialize)

        self.website_label = QtWidgets.QLabel("Website:")
        self.website_input = QtWidgets.QLineEdit()

        self.username_label = QtWidgets.QLabel("Benutzername:")
        self.username_input = QtWidgets.QLineEdit()

        self.password_label = QtWidgets.QLabel("Passwort:")
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)

        self.save_button = QtWidgets.QPushButton("Passwort speichern")
        self.save_button.clicked.connect(self.save_password)

        self.view_button = QtWidgets.QPushButton("Passwörter anzeigen")
        self.view_button.clicked.connect(self.view_passwords)

        self.layout = QtWidgets.QVBoxLayout()
        self.layout.addWidget(self.master_password_label)
        self.layout.addWidget(self.master_password_input)
        self.layout.addWidget(self.initialize_button)
        self.layout.addWidget(self.website_label)
        self.layout.addWidget(self.website_input)
        self.layout.addWidget(self.username_label)
        self.layout.addWidget(self.username_input)
        self.layout.addWidget(self.password_label)
        self.layout.addWidget(self.password_input)
        self.layout.addWidget(self.save_button)
        self.layout.addWidget(self.view_button)

        self.setLayout(self.layout)

    def initialize(self):
        master_password = self.master_password_input.text()
        self.pm.initialize(master_password)
        QtWidgets.QMessageBox.information(self, "Erfolg", "Passwort-Manager initialisiert!")

    def save_password(self):
        website = self.website_input.text()
        username = self.username_input.text()
        password = self.password_input.text()
        self.pm.save_password(website, username, password)
        QtWidgets.QMessageBox.information(self, "Erfolg", "Passwort erfolgreich gespeichert!")

    def view_passwords(self):
        passwords = self.pm.view_passwords()
        if not passwords:
            QtWidgets.QMessageBox.information(self, "Passwörter", "Keine Passwörter gespeichert.")
            return
        message = "\n".join([f"Website: {w}, Benutzername: {u}, Passwort: {p}" for w, u, p in passwords])
        QtWidgets.QMessageBox.information(self, "Gespeicherte Passwörter", message)


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
