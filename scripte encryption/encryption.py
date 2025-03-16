import os
import json
from hashlib import sha256

# Fichier pour sauvegarder la clé
CONFIG_FILE = "encryption_config.json"

def xor_encrypt_decrypt(data, key):
    """
    Chiffre ou déchiffre des données en utilisant l'opération XOR.
    """
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def generate_key(password):
    """
    Génère une clé à partir d'un mot de passe en utilisant SHA-256.
    """
    return sha256(password.encode('utf-8')).digest()

def save_key(key):
    """
    Sauvegarde la clé dans un fichier JSON.
    """
    config = {
        "key": key.hex()
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)
    print("Clé sauvegardée dans le fichier.")

def load_key():
    """
    Charge la clé depuis un fichier JSON.
    """
    if not os.path.exists(CONFIG_FILE):
        return None

    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)
        return bytes.fromhex(config["key"])

def encrypt_text(plaintext, key):
    """
    Chiffre un texte en utilisant XOR.
    """
    ciphertext = xor_encrypt_decrypt(plaintext.encode('utf-8'), key)
    return ciphertext.hex()

def decrypt_text(ciphertext_hex, key):
    """
    Déchiffre un texte en utilisant XOR.
    """
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext = xor_encrypt_decrypt(ciphertext, key)
    return plaintext.decode('utf-8')

def encrypt_file(file_path, key):
    """
    Chiffre un fichier en utilisant XOR.
    """
    try:
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        ciphertext = xor_encrypt_decrypt(plaintext, key)

        output_file_path = file_path + ".enc"
        with open(output_file_path, 'wb') as f:
            f.write(ciphertext)
        print(f"Fichier chiffré : {output_file_path}")
    except Exception as e:
        print(f"Erreur lors du chiffrement du fichier {file_path}: {e}")

def decrypt_file(file_path, key):
    """
    Déchiffre un fichier en utilisant XOR.
    """
    try:
        with open(file_path, 'rb') as f:
            ciphertext = f.read()

        plaintext = xor_encrypt_decrypt(ciphertext, key)

        output_file_path = file_path[:-4]  # Supprime l'extension .enc
        with open(output_file_path, 'wb') as f:
            f.write(plaintext)
        print(f"Fichier déchiffré : {output_file_path}")
    except Exception as e:
        print(f"Erreur lors du déchiffrement du fichier {file_path}: {e}")

def encrypt_folder(folder_path, key, output_folder):
    """
    Chiffre tous les fichiers d'un dossier.
    """
    if not os.path.exists(folder_path):
        print(f"Le dossier source '{folder_path}' n'existe pas.")
        return

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, folder_path)
            output_file_path = os.path.join(output_folder, relative_path + '.enc')

            os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

            encrypt_file(file_path, key)
    print(f"Dossier '{folder_path}' chiffré avec succès dans '{output_folder}'.")

def decrypt_folder(folder_path, key, output_folder):
    """
    Déchiffre tous les fichiers d'un dossier.
    """
    if not os.path.exists(folder_path):
        print(f"Le dossier source '{folder_path}' n'existe pas.")
        return

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.enc'):
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, folder_path)
                output_file_path = os.path.join(output_folder, relative_path[:-4])  # Supprime .enc

                os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

                decrypt_file(file_path, key)
    print(f"Dossier '{folder_path}' déchiffré avec succès dans '{output_folder}'.")

def main():
    key = load_key()

    if key is None:
        password = input("Aucune clé trouvée. Entrez un mot de passe pour générer une clé : ")
        key = generate_key(password)
        save_key(key)

    while True:
        choice = input(
            "Choisissez une option :\n"
            "1) Chiffrer\n"
            "2) Déchiffrer\n"
            "3) Paramètres\n"
            "Votre choix (1, 2 ou 3) : "
        )

        if choice == "1":
            sub_choice = input(
                "1) Chiffrer un texte\n"
                "2) Chiffrer un fichier\n"
                "3) Chiffrer un dossier\n"
                "4) Chiffrer une image\n"
                "Votre choix (1, 2, 3 ou 4) : "
            )
            if sub_choice == "1":
                plaintext = input("Entrez le texte à chiffrer : ")
                ciphertext = encrypt_text(plaintext, key)
                print("Texte chiffré (hex) :", ciphertext)
            elif sub_choice == "2":
                file_path = input("Entrez le chemin du fichier à chiffrer : ")
                encrypt_file(file_path, key)
            elif sub_choice == "3":
                folder_path = input("Entrez le chemin du dossier à chiffrer : ")
                output_folder = input("Entrez le chemin du dossier de sortie pour les fichiers chiffrés : ")
                encrypt_folder(folder_path, key, output_folder)
            elif sub_choice == "4":
                file_path = input("Entrez le chemin de l'image à chiffrer : ")
                encrypt_file(file_path, key)
            else:
                print("Choix invalide.")

        elif choice == "2":
            sub_choice = input(
                "1) Déchiffrer un texte\n"
                "2) Déchiffrer un fichier\n"
                "3) Déchiffrer un dossier\n"
                "4) Déchiffrer une image\n"
                "Votre choix (1, 2, 3 ou 4) : "
            )
            if sub_choice == "1":
                ciphertext_hex = input("Entrez le texte chiffré (en hexadécimal) : ")
                try:
                    decrypted_text = decrypt_text(ciphertext_hex, key)
                    print("Texte déchiffré :", decrypted_text)
                except ValueError as e:
                    print("Erreur lors du déchiffrement :", e)
            elif sub_choice == "2":
                file_path = input("Entrez le chemin du fichier à déchiffrer : ")
                decrypt_file(file_path, key)
            elif sub_choice == "3":
                folder_path = input("Entrez le chemin du dossier à déchiffrer : ")
                output_folder = input("Entrez le chemin du dossier de sortie pour les fichiers déchiffrés : ")
                decrypt_folder(folder_path, key, output_folder)
            elif sub_choice == "4":
                file_path = input("Entrez le chemin de l'image à déchiffrer : ")
                decrypt_file(file_path, key)
            else:
                print("Choix invalide.")

        elif choice == "3":
            sub_choice = input(
                "7) Générer une clé\n"
                "8) Changer la clé\n"
                "9) Sauvegarder la clé actuelle\n"
                "Votre choix (7, 8 ou 9) : "
            )
            if sub_choice == "7":
                password = input("Entrez un mot de passe pour générer une nouvelle clé : ")
                key = generate_key(password)
                print("Nouvelle clé générée.")
            elif sub_choice == "8":
                new_key_hex = input("Entrez la nouvelle clé (en hexadécimal, 64 caractères) : ")
                if len(new_key_hex) != 64:
                    print("La clé doit faire 64 caractères hexadécimaux.")
                else:
                    key = bytes.fromhex(new_key_hex)
                    print("Clé mise à jour avec succès.")
            elif sub_choice == "9":
                save_key(key)
            else:
                print("Choix invalide.")

        else:
            print("Choix invalide. Veuillez sélectionner 1, 2 ou 3.")

        continuer = input("Voulez-vous continuer ? (o/n) : ")
        if continuer.lower() != 'o':
            break

if __name__ == "__main__":
    main()
