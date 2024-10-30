import sqlite3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import os
import getpass

# Funktion zur Generierung eines Schlüssels aus einem Master-Passwort
def generate_key(master_password):
    # Erzeuge einen SHA-256 Hash des Master-Passworts als Schlüssel
    return hashlib.sha256(master_password.encode()).digest()

# Funktion zur Verschlüsselung eines Passworts
def encrypt_password(key, password):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(password.encode())
    return cipher.nonce, tag, ciphertext

# Funktion zur Entschlüsselung eines Passworts
def decrypt_password(key, nonce, tag, ciphertext):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_password.decode()

# Funktion zur Erstellung der Datenbank
def create_db():
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                      (id INTEGER PRIMARY KEY, website TEXT, username TEXT, nonce BLOB, tag BLOB, ciphertext BLOB)''')
    conn.commit()
    conn.close()

# Funktion zum Speichern eines Passworts
def save_password(master_password, website, username, password):
    key = generate_key(master_password)
    nonce, tag, ciphertext = encrypt_password(key, password)

    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (website, username, nonce, tag, ciphertext) VALUES (?, ?, ?, ?, ?)",
                   (website, username, nonce, tag, ciphertext))
    conn.commit()
    conn.close()
    print("Passwort erfolgreich gespeichert!")

# Funktion zum Abrufen aller gespeicherten Passwörter
def view_passwords(master_password):
    key = generate_key(master_password)
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords")
    rows = cursor.fetchall()
    for row in rows:
        website = row[1]
        username = row[2]
        nonce = row[3]
        tag = row[4]
        ciphertext = row[5]
        decrypted_password = decrypt_password(key, nonce, tag, ciphertext)
        print(f"Website: {website}, Benutzername: {username}, Passwort: {decrypted_password}")
    conn.close()

# Hauptmenü
def main():
    create_db()

    master_password = getpass.getpass("Geben Sie Ihr Master-Passwort ein: ")

    while True:
        choice = input("Wählen Sie eine Option:\n1. Passwort speichern\n2. Gespeicherte Passwörter anzeigen\n3. Beenden\n")
        if choice == "1":
            website = input("Website: ")
            username = input("Benutzername: ")
            password = getpass.getpass("Passwort: ")  # Passwort nicht im Klartext eingeben
            save_password(master_password, website, username, password)
        elif choice == "2":
            view_passwords(master_password)
        elif choice == "3":
            break
        else:
            print("Ungültige Auswahl. Bitte versuchen Sie es erneut.")

if __name__ == "__main__":
    main()
