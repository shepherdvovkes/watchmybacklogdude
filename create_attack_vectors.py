# create_attack_vectors.py
import numpy as np
import faiss
from sentence_transformers import SentenceTransformer
import os

print("Загрузка модели Sentence Transformer. Это может занять некоторое время...")
# Мы используем модель, которая хорошо подходит для коротких текстов и семантического поиска.
# 'all-MiniLM-L6-v2' — отличный баланс скорости и качества.
model = SentenceTransformer('all-MiniLM-L6-v2')

# Расширенный список известных паттернов атак, угроз и неправильных конфигураций для macOS.
# Этот список основан на фреймворке MITRE ATT&CK для macOS и охватывает Intel и Apple Silicon.
known_security_patterns = [
    # --- Persistence (Закрепление в системе) ---
    "Launch agent or daemon created in /Library/LaunchAgents/",
    "Launch agent or daemon created in /Library/LaunchDaemons/",
    "User-specific launch agent created in ~/Library/LaunchAgents/",
    "User added a new login item to system preferences",
    "cron job created or modified for user",
    "emond rule added for event-driven persistence",
    "Periodic script execution configured via launchd",
    "SSH authorized_keys file was modified",
    "New user account created with administrative privileges",

    # --- Privilege Escalation (Повышение привилегий) ---
    "sudo: a password is required for a user",
    "sudo: user is not in the sudoers file",
    "Process with UID 0 (root) started by non-system user",
    "Attempt to modify a SUID or SGID binary",
    "Exploiting vulnerability to gain root privileges",
    "System Integrity Protection (SIP) was disabled",
    "Authorization database was modified to grant privileges",

    # --- Defense Evasion (Обход защиты) ---
    "Clearing or modification of system logs in /var/log/",
    "Attempt to disable Gatekeeper using spctl --master-disable",
    "TCC.db (Transparency, Consent, and Control database) modification attempt",
    "History file like .bash_history or .zsh_history was deleted or cleared",
    "Process masquerading as a common system process like mdworker or launchd",
    "Disabling or tampering with XProtect or MRT (Malware Removal Tool)",
    "Using osascript to run unsigned code to bypass security controls",
    "File hidden by prepending a dot or using chflags hidden",
    "Timestomping a file to modify its creation or modification date",

    # --- Credential Access (Доступ к учетным данным) ---
    "Attempt to read or dump keychain contents from login.keychain-db",
    "Process accessing SSH keys in ~/.ssh/",
    "Process reading browser profile data for stored credentials",
    "Searching for files containing 'password', 'private_key', or 'secret'",
    "Security-sensitive information requested via command-line",

    # --- Execution (Исполнение) ---
    "Execution of script from /tmp or /var/tmp directory",
    "AppleScript (osascript) executing suspicious commands like network requests",
    "Python script making an outbound network connection",
    "Shell script downloaded and executed with curl and sh",
    "Untrusted or unsigned application was executed for the first time",
    "Microsoft Office document spawned a shell process like /bin/bash",
    "Application requested permissions to run a script",

    # --- Discovery (Разведка) ---
    "system_profiler command used to gather detailed system information",
    "whoami, ifconfig, netstat, or ps commands used for system reconnaissance",
    "Scanning local network with nmap or similar tools",
    "Enumerating installed applications in /Applications/",
    "Checking for virtualization environment",

    # --- Exfiltration & Command and Control (Эксфильтрация и C2) ---
    "Outbound network connection to a known malicious IP or C2 domain",
    "Data being sent over a non-standard port like 4444 or 8080",
    "Large amount of data uploaded via curl, scp, or nc (netcat)",
    "DNS queries to suspicious or DGA (Domain Generation Algorithm) domains",
    "Process listening for incoming connections on a high-numbered port",

    # --- Initial Access (Первоначальный доступ) ---
    "failed password for invalid user",
    "accepted publickey for user from a remote host",
    "repeated logon failures for a single user account",
    "Java applet or Web Start application was launched from a browser",

    # --- MDM & Configuration Profile Hijacking ---
    "MDM profile installed without user consent",
    "Suspicious or unverified configuration profile (.mobileconfig) installed",
    "MDM server sending remote wipe or lock command",
    "Attempt to bypass MDM enrollment or restrictions",
    "MDM client process 'mdmclient' exhibiting unusual activity like high CPU usage",
    "Profile removal command executed outside of System Preferences using 'profiles' command",
    "A new root certificate was installed from a configuration profile",

    # --- Secure Enclave & T2 Chip Exploitation ---
    "Multiple failed authentication attempts to Secure Enclave",
    "Unauthorized process attempting to access Secure Enclave Processor (sep)",
    "Tampering with BridgeOS software update process",
    "Failed Touch ID or biometric authentication log spam",
    "Process attempting to access or exfiltrate data from an encrypted APFS volume",
    "Anomalous behavior from kernel_task related to T2 security chip operations",
    "A process is trying to enumerate or interact with IOKit drivers for Apple T2",

    # --- Hardware & Firmware Attacks (USB, DFU, Thunderbolt) ---
    "New USB device with combined HID and Mass Storage capabilities detected (potential BadUSB)",
    "Unauthorized USB device class connected (e.g., network interface, serial port)",
    "Process making direct raw access to a USB device file in /dev/",
    "Thunderbolt security level modified or disabled via nvram",
    "Potential Direct Memory Access (DMA) attack initiated over a Thunderbolt port",
    "Device unexpectedly entered DFU (Device Firmware Update) mode without user action",
    "Execution of DFU exploitation tools like 'checkm8' or 'ipwndfu' detected in process list",
    "Communication with a device in DFU mode by an unauthorized process",
    "Multiple consecutive failed DFU restore attempts logged",
    "Anomalous I/O activity on USB ports, such as rapid connect/disconnect cycles",
]


print(f"Кодирование {len(known_security_patterns)} паттернов в векторы...")
# Преобразуем текстовые описания в числовые векторы (embeddings).
attack_vectors = model.encode(known_security_patterns, show_progress_bar=True)

# Убедимся, что директория для данных существует
os.makedirs('data', exist_ok=True)
vector_db_path = 'data/attack_vectors.index'
patterns_path = 'data/attack_patterns.txt'

print("Создание индекса FAISS для быстрого поиска...")
# Получаем размерность векторов (для all-MiniLM-L6-v2 это 384)
dimension = attack_vectors.shape[1]
# Создаем простой L2-индекс. Он хорошо подходит для поиска по косинусному расстоянию после нормализации.
index = faiss.IndexFlatL2(dimension)
# Добавляем наши векторы в индекс.
index.add(attack_vectors)

print(f"Индекс создан. Сохранение в файл: {vector_db_path}")
faiss.write_index(index, vector_db_path)

print(f"Сохранение текстовых паттернов в файл: {patterns_path}")
with open(patterns_path, "w") as f:
    for pattern in known_security_patterns:
        f.write(pattern + "\n")

print("\nГотово! Расширенная база векторов для RAG успешно создана.")

