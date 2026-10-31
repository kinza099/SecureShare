# Security Testing & Verification Report
## Secure File Sharing System
**Subject:** Secure Software Design and Development (SSDD)  
**Program:** BS Cyber Security – 8th Semester  
**Date Generated:** 2026-11-01 00:31:43  
**Test Suite Status:** ALL 20 TEST CASES PASSED (0 FAILURES)  
**Total Security Test Cases:** 20 | **Passed:** 20 | **Failed:** 0  

---

### Security Test Case Execution Matrix

| Test Case ID | Security Feature / Control | Testing Procedure | Expected Result | Actual Result | Status |
|---|---|---|---|---|:---:|
| **TC-AUTH-01** | Password Complexity & Registration Policy | Submitted multiple weak passwords lacking uppercase, digits, or symbols during registration. | System rejects weak passwords; requires minimum 8 characters with alphanumeric and special characters. | Enforced by custom Regex and Django validators; all weak variants rejected. | **✅ PASS** |
| **TC-AUTH-02** | Argon2id Password Storage (RFC 9106 / OWASP) | Inspected database hash prefix for newly registered user account. | Password stored as memory-hard Argon2id hash ($argon2id$v=19$m=65536,t=3,p=4$...). | Verified Argon2PasswordHasher as primary hasher in settings and database. | **✅ PASS** |
| **TC-AUTH-03** | Brute-Force & Credential Stuffing Lockout | Submitted 5 consecutive invalid passwords for an active user account. | Account locked for 15 minutes; subsequent authentication attempts blocked. | User lockout_until updated; account locked; SecurityEvent alert triggered. | **✅ PASS** |
| **TC-AUTH-04** | Role-Based Access Control (RBAC) Isolation | Authenticated as standard user and attempted HTTP GET to /monitoring/admin/users/. | Access denied; administrative endpoints restricted to verified administrators. | Redirected / access denied via user_passes_test; non-admin blocked. | **✅ PASS** |
| **TC-AUTH-05** | Account Suspension & Deactivation Rejection | Admin suspended user account; user attempted login with valid credentials. | Authentication rejected with deactivation notice; session not established. | Login rejected with status SUSPENDED in login history audit. | **✅ PASS** |
| **TC-CRYPTO-01** | AES-256-GCM Authenticated Encryption & Decryption | Encrypted file payload, unwrapped DEK, and performed AEAD decryption. | Plaintext recovered byte-for-byte with valid 128-bit authentication tag. | Round-trip successful; exact plaintext match verified. | **✅ PASS** |
| **TC-CRYPTO-02** | NIST SP 800-38F Key Wrap Architecture | Wrapped 256-bit DEK using Master KEK with aes_key_wrap; unwrapped in volatile RAM. | Unwrapped DEK matches original; raw DEK never persisted in database. | Key wrapped to 40 bytes; unwrapped to identical 32 bytes in memory. | **✅ PASS** |
| **TC-CRYPTO-03** | AES-GCM Authentication Tag Tamper Detection | Flipped single bit in encrypted ciphertext on disk and attempted decryption. | Cryptography InvalidTag raised; DecryptionIntegrityError triggered. | InvalidTag intercepted; download rejected; CRITICAL security alert raised. | **✅ PASS** |
| **TC-CRYPTO-04** | SHA-256 Plaintext Digest Integrity Check | Supplied corrupted expected SHA-256 hash to decryption service. | Decryption rejected and file access denied. | Integrity mismatch caught; DecryptionIntegrityError raised. | **✅ PASS** |
| **TC-CRYPTO-05** | Cryptographic Nonce Replay Prevention | Generated 50 consecutive nonces and evaluated collision set. | Zero nonce reuse across files (50 unique 96-bit nonces). | 50 unique random nonces generated with zero collisions. | **✅ PASS** |
| **TC-SHARE-01** | Granular Sharing Permissions (Viewer vs Downloader) | Shared file as VIEWER; recipient attempted direct download endpoint. | Download blocked with HTTP 403 Forbidden; preview permitted. | HTTP 403 returned; permission enforced strictly by backend service. | **✅ PASS** |
| **TC-SHARE-02** | Password-Protected Public Link Verification | Created link with access password; tested invalid password, then valid password. | Invalid password denied; valid password unlocks decrypted download. | Prompted for password; invalid denied; valid verified via Argon2id/PBKDF2. | **✅ PASS** |
| **TC-SHARE-03** | Time-Bound Link Expiration | Set link expiration timestamp in past; attempted access via token. | HTTP 403 Forbidden returned; link expired notice presented. | Access blocked with HTTP 403; security event recorded. | **✅ PASS** |
| **TC-SHARE-04** | Instant Link Revocation | File owner revoked link; accessed public link token. | Access immediately denied with revoked notice. | Access blocked with HTTP 403; link marked revoked in audit log. | **✅ PASS** |
| **TC-SHARE-05** | Atomic Download Counter & Limit Enforcement | Set max_downloads=1; downloaded file twice through link token. | Download #1 succeeds; Download #2 denied as limit reached. | Atomic F() increment enforced; second attempt blocked with HTTP 403. | **✅ PASS** |
| **TC-SEC-01** | Insecure Direct Object Reference (IDOR) Prevention | User B queried User A private file UUID via /files/download/<uuid>/. | Access blocked with HTTP 403 Forbidden. | Object-level permission check blocked request with HTTP 403. | **✅ PASS** |
| **TC-SEC-02** | Malicious Executable & Script Upload Prevention | Attempted upload of .exe, .bat, .sh, .py, and .php payloads. | ValidationError raised; file rejected before processing. | Prohibited extension check rejected all test payloads. | **✅ PASS** |
| **TC-SEC-03** | File Signature / Magic Byte Spoofing Protection | Renamed plaintext file to sample.pdf without valid %PDF magic bytes. | Signature mismatch caught; upload blocked. | Magic byte validator detected header mismatch; upload rejected. | **✅ PASS** |
| **TC-SEC-04** | Scoped Duplicate File Detection | Checked user upload against existing SHA-256 hashes within user account. | Warns user of duplicate; does NOT leak duplicate status of other users. | Duplicate flagged within Alice account; Bob query returned None. | **✅ PASS** |
| **TC-SEC-05** | HTTP Security Response Headers | Inspected HTTP response headers on file download/preview. | X-Content-Type-Options: nosniff present; strict MIME isolation enforced. | Header present with value "nosniff"; CSP active. | **✅ PASS** |

---

### Cryptographic & Architectural Verification Summary
1. **Confidentiality (AES-256-GCM + NIST SP 800-38F Key Wrap):**
   - Every uploaded file and file version is encrypted with an isolated 256-bit Data Encryption Key (DEK).
   - Raw DEKs are never saved in MySQL; they are wrapped using the Master Key Encryption Key (KEK) and stored as hex.
   - Master KEK is kept outside the database in protected environment variables / local keyfile.

2. **Integrity & Authenticity (AEAD Tag + SHA-256 Digest):**
   - Ciphertexts include a 128-bit authentication tag verified by `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.
   - Bit-flipping and ciphertext tampering immediately raise `InvalidTag` and trigger high-priority security audit alerts.
   - SHA-256 digests are computed pre-encryption and re-verified post-decryption before any file bytes are delivered.

3. **Authentication & Brute-Force Resistance (Argon2id + 15-Minute Lockout):**
   - User passwords are automatically hashed with memory-hard Argon2id (RFC 9106 recommended by OWASP).
   - 5 consecutive failed login attempts trigger an automatic 15-minute temporary lockout.

4. **Authorization & Zero-Trust (RBAC + Object-Level Ownership Checks):**
   - Direct object reference attacks (IDOR) are denied with HTTP 403.
   - Granular permissions (Viewer vs Downloader) prevent unauthorized downloads while allowing secure document previewing.
   - **Administrator Zero-Trust:** System administrators can view system-wide file metadata and audit events but cannot decrypt users' private files.

5. **Local Network / Wi-Fi Demonstration:**
   - Server binds to `0.0.0.0:8000`, dynamically discovering the host's LAN IPv4 address.
   - Sharing links and mobile QR codes automatically embed the reachable LAN IP for seamless cross-device mobile access.