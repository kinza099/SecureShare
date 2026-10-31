# Secure File Sharing System
### Secure Software Design and Development (SSDD) — Open-Ended Lab Project
**Degree Program:** BS Cyber Security – 8th Semester  
**Stack:** Python 3.11+ | Django 5.x/6.x | MySQL 8.x | AES-256-GCM | Argon2id | LAN/Wi-Fi Deployment

---

## 1. Project Overview
The **Secure File Sharing System** is a real-world, security-hardened web application designed to guarantee the five fundamental pillars of information assurance across local networks and Wi-Fi environments:
- **Confidentiality:** Every file payload is encrypted using **AES-256-GCM** with a distinct 256-bit Data Encryption Key (DEK). DEKs are wrapped using a Master Key Encryption Key (KEK) via **NIST SP 800-38F Key Wrap**; raw DEKs are never saved in the database or written to disk.
- **Integrity & Authenticity:** Validated via **128-bit AES-GCM authentication tags** and **SHA-256 cryptographic digests** computed pre-encryption and re-verified post-decryption before any file stream is delivered.
- **Authentication:** Enforced using **Argon2id** (RFC 9106 memory-hard algorithm), strong password complexity regex policies, session expiration, and automatic **15-minute account lockouts** after 5 consecutive failed attempts.
- **Authorization (RBAC & Zero-Trust):** Role-Based Access Control separating Standard Users from Administrators. Includes granular **Viewer** (preview only) vs **Downloader** permissions, object-level ownership checks (preventing IDOR), and an explicit **Administrator Zero-Trust Policy** where system admins can inspect metadata but cannot decrypt users' private files.
- **Accountability:** Centralized, immutable, tamper-evident audit logging for all authentication attempts, file operations, link accesses, and suspicious anomalies.

---

## 2. Cryptographic Architecture & Workflow

```
+---------------------------------------------------------------------------------------+
|                               FILE ENCRYPTION PIPELINE                                |
+---------------------------------------------------------------------------------------+
 [User File Upload]
        |
        v
 [Magic Byte & Extension Validation] ---> (Rejects scripts / executables / spoofed files)
        |
        v
 [Compute SHA-256 Plaintext Hash]
        |
        +---> [Generate 256-bit Random DEK]
        |           |
        |           +---> [NIST SP 800-38F Key Wrap with Master KEK] ---> [Store Wrapped DEK in DB]
        |           |
        +---> [Generate 96-bit Random Nonce] -----------------------------> [Store Nonce in DB]
        |
        v
 [AES-256-GCM Encryption] ---> [Ciphertext + 128-bit Auth Tag]
        |
        v
 [Store in private_storage/<uuid>.enc outside Web Root]
```

```
+---------------------------------------------------------------------------------------+
|                               FILE DECRYPTION PIPELINE                                |
+---------------------------------------------------------------------------------------+
 [Download / Preview Request]
        |
        v
 [Verify Authentication & Object-Level Permission (Owner / Downloader / Link Token)]
        |
        v
 [Fetch Wrapped DEK & Nonce from DB] ---> [Unwrap DEK in RAM using Master KEK]
        |
        v
 [Read Ciphertext from private_storage/<uuid>.enc]
        |
        v
 [AES-256-GCM Decrypt & Verify 128-bit Auth Tag]
        |
        +---> [If Tag Invalid] ---> [Raise DecryptionIntegrityError & Trigger High-Severity Alert]
        |
        v
 [Compute Plaintext SHA-256 Digest]
        |
        +---> [Compare with Expected Pre-encryption Hash]
        |
        v (Verified)
 [Stream Plaintext to Client with Strict Security Headers (X-Content-Type-Options: nosniff)]
```

---

## 3. Database Schema (MySQL 8.x / Django ORM)

```
       +-----------------------+              1 : 1              +----------------------------+
       |     accounts_user     | ------------------------------> |   filemanager_filerecord   |
       +-----------------------+                                 +----------------------------+
       | id (PK)               |                                 | id (UUID, PK)              |
       | username, email       |                                 | owner_id (FK -> User)      |
       | password (Argon2id)   |                                 | display_name               |
       | is_admin, is_suspended|                                 | file_type, file_size       |
       | failed_login_attempts |                                 | sha256_hash                |
       | lockout_until         |                                 | current_version            |
       | last_login_ip         |                                 +----------------------------+
       +-----------------------+                                               |
             |           |                                                     | 1 : 1
             |           | 1 : N                                               v
             |           +-------------------> +--------------------------------------------+
             |                                 |     filemanager_fileencryptionmetadata     |
             v 1 : N                           +--------------------------------------------+
       +-----------------------+               | id (PK)                                    |
       | accounts_loginhistory |               | file_record_id (OneToOne -> FileRecord)    |
       +-----------------------+               | stored_filename (UUID.enc)                 |
       | id (PK), ip_address   |               | wrapped_dek (Hex wrapped with Master KEK)  |
       | status, timestamp     |               | nonce (96-bit Hex)                         |
       +-----------------------+               | algorithm (AES-256-GCM)                    |
                                               | integrity_status (VERIFIED / FAILED)       |
                                               +--------------------------------------------+
                                                               |
                                                               | 1 : N
                                                               v
                                               +--------------------------------------------+
                                               |          filemanager_fileversion           |
                                               +--------------------------------------------+
                                               | id (PK), file_record_id (FK)               |
                                               | version_number, stored_filename            |
                                               | sha256_hash, wrapped_dek, nonce            |
                                               +--------------------------------------------+
                                                               |
                                   +---------------------------+----------------------------+
                                   | 1 : N                                                  | 1 : N
                                   v                                                        v
       +--------------------------------------------+              +--------------------------------------------+
       |             sharing_fileshare              |              |            sharing_sharinglink             |
       +--------------------------------------------+              +--------------------------------------------+
       | id (UUID, PK)                              |              | id (UUID, PK)                              |
       | file_record_id (FK -> FileRecord)          |              | file_record_id (FK -> FileRecord)          |
       | sender_id (FK -> User)                     |              | creator_id (FK -> User)                    |
       | recipient_id (FK -> User)                  |              | token_hash (SHA-256 hash of token)         |
       | permission ('VIEWER' / 'DOWNLOADER')       |              | is_password_protected, password_hash       |
       | expires_at, is_revoked                     |              | max_downloads, download_count              |
       +--------------------------------------------+              | expires_at, is_revoked                     |
                                                                   +--------------------------------------------+
```

---

## 4. LAN / Wi-Fi Network Deployment Architecture

One laptop acts as the host server connected to the Wi-Fi network. Other devices (smartphones, laptops) connect to the application via the host laptop's local IPv4 address.

```
       +-----------------------------------------------------------+
       |                 LOCAL WI-FI NETWORK ROUTER                |
       |                  Subnet: 192.168.1.0/24                   |
       +-----------------------------------------------------------+
                     |                          |
                     |                          |
                     v                          v
       +---------------------------+    +-------------------------------+
       | HOST LAPTOP (SERVER)      |    | CLIENT DEVICES (ON WI-FI)     |
       | IP: 192.168.1.100         |    | Device 1 (Alice): Laptop      |
       | Django binds: 0.0.0.0:8000|    | Device 2 (Bob): Android Phone |
       | MySQL: localhost:3306     |    | Device 3 (Charlie): Tablet    |
       | Storage: private_storage/ |    | URL: http://192.168.1.100:8000|
       +---------------------------+    +-------------------------------+
```

### LAN Security Safeguards:
1. **Database Isolation:** MySQL port 3306 is bound exclusively to `127.0.0.1` and is never exposed to the local network.
2. **Encrypted Storage Isolation:** Files reside in `private_storage/` outside the web root and cannot be browsed directly.
3. **No Authentication Bypass:** Every request across LAN requires session cookies and CSRF verification.
4. **Key Isolation:** Master KEK and encryption functions run strictly server-side on the host machine.
5. **Dynamic LAN IP Detection:** The host automatically detects its Wi-Fi IPv4 address and embeds it into generated sharing links and QR codes.

---

## 5. Step-by-Step Installation Guide (Windows 10 / Windows 11)

### Step 1: Open PowerShell
Open PowerShell as Administrator (to configure firewall) or normal user.

### Step 2: Clone / Navigate to the Project Directory
```powershell
cd c:\Users\kinza\OneDrive\Desktop\SSDD_OEL_PROJECT
```

### Step 3: Create & Activate Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 4: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 5: Database Configuration
The application is pre-configured to support both **MySQL 8.x** and **SQLite3** seamlessly.
- **To use MySQL 8.x:**
  1. Ensure MySQL server is running on port 3306.
  2. Create the database in MySQL:
     ```sql
     CREATE DATABASE secure_file_sharing CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
     ```
  3. In `.env`, set:
     ```env
     DB_ENGINE=mysql
     DB_NAME=secure_file_sharing
     DB_USER=root
     DB_PASSWORD=your_mysql_password
     DB_HOST=127.0.0.1
     DB_PORT=3306
     ```
- **To use SQLite3 (Instant testing):**
  Set `DB_ENGINE=sqlite3` in `.env`.

### Step 6: Apply Database Migrations
```powershell
python manage.py migrate
```

### Step 7: Seed Demonstration Test Accounts
Run the automated seed command to populate the database with default test accounts, sample files, and security event logs:
```powershell
python manage.py seed_demo_data
```
**Default Seeded Accounts:**
- **System Administrator:** `admin` / `Admin@12345`
- **User A (Alice):** `alice` / `Alice@12345`
- **User B (Bob):** `bob` / `Bob@12345`
- **User C (Charlie):** `charlie` / `Charlie@12345`

### Step 8: Allow Application Port Through Windows Firewall
Run in PowerShell (Run as Administrator once):
```powershell
netsh advfirewall firewall add rule name="Django_LAN_SSDD" dir=in action=allow protocol=TCP localport=8000
```

### Step 9: Find Your Host Laptop's Local Wi-Fi IPv4 Address
```powershell
ipconfig
```
Look for `IPv4 Address` under your active Wi-Fi adapter (e.g. `192.168.1.100`).

### Step 10: Launch the Application Bound to LAN Interface
```powershell
python manage.py runserver 0.0.0.0:8000
```
Open your browser at:
`http://localhost:8000/` or `http://<YOUR_LAN_IP>:8000/`

---

## 6. Live Demonstration Scenario (Lab Evaluation Guide)

Follow this demonstration flow to demonstrate all required SSDD learning outcomes:

### Scenario 1: Host Laptop & User A (Alice)
1. Open `http://localhost:8000/` and log in as `alice` (`Alice@12345`).
2. Navigate to **Upload Files**; select a PDF or Document (`Report.pdf`).
3. Click **Encrypt & Save File**. Explain to the evaluator:
   - File is parsed, magic bytes verified.
   - Unique 256-bit DEK & 96-bit nonce generated.
   - Payload encrypted with AES-256-GCM.
   - DEK wrapped with Master KEK and stored in DB.
   - Original file hash (SHA-256) recorded.
4. Go to **My Files** -> Click **File Details**. Show the cryptographic parameters:
   - Stored File UUID (`private_storage/<uuid>.enc`).
   - Wrapped DEK hex.
   - Verified integrity badge.
5. Click **Link & QR**:
   - Check **Require Password Protection** -> set password `Secret123`.
   - Set max downloads: `5`.
   - Click **Generate Link & QR Code**.
   - Show the QR code modal on screen.

### Scenario 2: Device 2 (Bob's Phone / Second Laptop on Same Wi-Fi)
1. Ensure the device is connected to the same Wi-Fi.
2. Scan the QR code with the smartphone camera (or enter `http://192.168.1.x:8000/` in mobile browser).
3. The public link page opens. It shows:
   - File name, file size, SHA-256 digest preview.
   - Password prompt.
4. Enter `Secret123` -> Click **Verify Password**.
5. Click **Decrypt & Download File**.
6. The browser downloads the decrypted file. Point out:
   - Server unwrapped DEK in RAM.
   - AES-GCM tag verified.
   - SHA-256 digest matched before download.

### Scenario 3: Device 3 (Attacker / Unauthorized Access / Charlie)
1. Log in as `charlie` (`Charlie@12345`).
2. Attempt to directly download Alice's private unshared file by pasting its URL (`/files/download/<uuid>/`).
3. Result: **HTTP 403 Forbidden** (IDOR prevented).
4. Attempt to access a revoked or expired link.
5. Result: **Access Denied / Link Unavailable**.
6. Attempt 5 incorrect logins on Charlie's account.
7. Result: **Account temporarily locked out for 15 minutes**.

### Scenario 4: Administrator Control & Audit Monitoring
1. Log in as `admin` (`Admin@12345`).
2. Open **Admin Dashboard**:
   - Show real database metrics (users, encrypted files, vault storage).
   - Show the LAN Host Endpoint banner.
3. Open **Security Audit Logs** (`/monitoring/admin/logs/`):
   - Highlight the immutable log entries for Alice's upload, Bob's download, and Charlie's blocked access.
4. Open **Suspicious Activity Alerts** (`/monitoring/admin/suspicious/`):
   - Show the high-severity alert triggered for multiple failed logins.
   - Demonstrate the "Mark Reviewed" admin action.
5. Open **File Statistics** (`/monitoring/admin/files/`):
   - Highlight the **Zero-Trust Badge**: Point out that administrators can inspect metadata and hashes, but the application intentionally provides NO decrypt/download button for users' private files.

---

## 7. Automated Security Test Suite & Report

Execute the comprehensive 20-test automated security suite:
```powershell
python manage.py test tests
```
Generate the official downloadable report:
```powershell
python tests/generate_report.py
```
This produces `SECURITY_TESTING_REPORT.md` documenting all 20 security test cases, testing procedures, expected results, and verification statuses.

---

## 8. Summary of SSDD Security Controls Implemented

| Security Domain | Control Implemented | Verification Mechanism |
|---|---|---|
| **Confidentiality** | AES-256-GCM symmetric payload encryption | `tests/test_encryption.py` (TC-CRYPTO-01) |
| **Key Management** | NIST SP 800-38F Key Wrap (Master KEK wrapping DEKs) | `tests/test_encryption.py` (TC-CRYPTO-02) |
| **Integrity** | 128-bit GCM Auth Tag & SHA-256 Pre/Post Verification | `tests/test_encryption.py` (TC-CRYPTO-03, TC-CRYPTO-04) |
| **Authentication** | Argon2id password hashing (RFC 9106) | `tests/test_auth.py` (TC-AUTH-02) |
| **Brute-Force Protection**| 5-attempt threshold -> 15-minute lockout | `tests/test_auth.py` (TC-AUTH-03) |
| **Authorization (RBAC)** | Role-Based Access Control (Admin vs Standard User) | `tests/test_auth.py` (TC-AUTH-04) |
| **IDOR Protection** | Object-level ownership & sharing permission checks | `tests/test_security_controls.py` (TC-SEC-01) |
| **Upload Security** | Magic byte validation & executable extension rejection | `tests/test_security_controls.py` (TC-SEC-02, TC-SEC-03) |
| **Link Security** | SHA-256 token hashing, password protection, atomic max DL | `tests/test_sharing.py` (TC-SHARE-02, TC-SHARE-05) |
| **Accountability** | Centralized immutable audit logs & suspicious detection | `monitoring/models.py` & `monitoring/services.py` |
| **Cross-Platform LAN** | 0.0.0.0 binding, auto IP discovery & QR generation | `accounts/context_processors.py` & `sharing/services.py` |

---
*Developed for BS Cyber Security – 8th Semester Open-Ended Lab: Secure Software Design and Development (SSDD).*
