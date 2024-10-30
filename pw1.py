import sqlite3
import secrets
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import os
import getpass
from base64 import b64encode, b64decode
import sys


class PasswordManager:
    def __init__(self, db_path="passwords.db"):
        self.db_path = db_path
        self.salt = None
        self.key = None
        self.iterations = 500000  # Höhere Iteration für bessere Sicherheit

    def generate_key(self, master_password):
        if not self.salt:
            self.salt = secrets.token_bytes(32)  # Verwende secrets.token_bytes für sichere Zufallsbytes
        return hashlib.pbkdf2_hmac(
            'sha256',
            master_password.encode(),
            self.salt,
            self.iterations
        )

    def encrypt_password(self, password):
        if not self.key:
            raise ValueError("Schlüssel nicht initialisiert")
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(password.encode())
        return cipher.nonce, tag, ciphertext

    def decrypt_password(self, nonce, tag, ciphertext):
        if not self.key:
            raise ValueError("Schlüssel nicht initialisiert")
        try:
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted_password.decode()
        except (ValueError, KeyError):
            return "Entschlüsselung fehlgeschlagen - falsches Master-Passwort"

    def create_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                          (id INTEGER PRIMARY KEY,
                           website TEXT NOT NULL,
                           username TEXT NOT NULL,
                           nonce BLOB NOT NULL,
                           tag BLOB NOT NULL,
                           ciphertext BLOB NOT NULL,
                           created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

            cursor.execute('''CREATE TABLE IF NOT EXISTS metadata
                          (id INTEGER PRIMARY KEY,
                           salt BLOB NOT NULL,
                           created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
            conn.commit()

    def initialize(self, master_password):
        self.create_db()

        # Generiere einen neuen Salt, wenn er nicht existiert
        if not self.salt:
            self.salt = secrets.token_bytes(32)  # Erstelle einen neuen Salt

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT salt FROM metadata LIMIT 1")
            result = cursor.fetchone()

            if result:
                self.salt = result[0]
            else:
                # Hier muss self.salt gesetzt sein, also verwenden wir den generierten Salt
                cursor.execute("INSERT INTO metadata (salt) VALUES (?)", (self.salt,))
                conn.commit()

            self.key = self.generate_key(master_password)

    def save_password(self, website, username, password):
        if not all([website, username, password]):
            raise ValueError("Alle Felder müssen ausgefüllt sein")

        nonce, tag, ciphertext = self.encrypt_password(password)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO passwords (website, username, nonce, tag, ciphertext)
                VALUES (?, ?, ?, ?, ?)
            """, (website, username, nonce, tag, ciphertext))
            conn.commit()
        return True

    def view_passwords(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM passwords ORDER BY website")
            return [(row[1], row[2],
                     self.decrypt_password(row[3], row[4], row[5]))
                    for row in cursor.fetchall()]


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def main():
    clear_screen()
    print("=== Sicherer Passwort-Manager ===")

    pm = PasswordManager()

    try:
        master_password = getpass.getpass("Master-Passwort eingeben: ")
        pm.initialize(master_password)

        while True:
            clear_screen()
            print("\n1. Passwort speichern")
            print("2. Passwörter anzeigen")
            print("3. Beenden")

            try:
                choice = input("\nWählen Sie eine Option (1-3): ").strip()

                if choice == "1":
                    website = input("Website: ").strip()
                    username = input("Benutzername: ").strip()
                    password = getpass.getpass("Passwort: ")

                    if pm.save_password(website, username, password):
                        print("\n✓ Passwort erfolgreich gespeichert!")
                                        input("\nDrücken Sie Enter zum Fortfahren...")

                elif choice == "2":
                    passwords = pm.view_passwords()
                    if not passwords:
                        print("\nKeine Passwörter gespeichert.")
                    else:
                        print("\nGespeicherte Passwörter:")
                        print("-" * 50)
                        for website, username, password in passwords:
                            print(f"Website: {website}")
                            print(f"Benutzername: {username}")
                            print(f"Passwort: {password}")
                            print("-" * 50)
                    input("\nDrücken Sie Enter zum Fortfahren...")

                elif choice == "3":
                    print("\nProgramm wird beendet...")
                    break

                else:
                    print("\nUngültige Auswahl!")
                    input("Drücken Sie Enter zum Fortfahren...")

            except Exception as e:
                print(f"\nFehler: {str(e)}")
                input("Drücken Sie Enter zum Fortfahren...")

    except KeyboardInterrupt:
        print("\n\nProgramm wird beendet...")
    except Exception as e:
        print(f"\nKritischer Fehler: {str(e)}")


if __name__ == "__main__":
    main()
