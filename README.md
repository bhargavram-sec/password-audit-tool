![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-educational-orange)

# Password Audit & Recovery Tool 🔐

A Python-based **Password Audit & Recovery Tool** designed for **educational purposes, digital forensics labs, and authorized security testing**.

This tool helps evaluate password strength for hashes and encrypted files using multiple attack strategies.

---

## ⚠️ Disclaimer

This project is intended **strictly for educational use, cybersecurity labs, and authorized password recovery**.

Use this tool **only on systems, files, or hashes that you own or have explicit permission to test**.  
The author is **not responsible for misuse** of this software.

---

## 🧠 Threat Model & Use Case

This tool simulates common password attack techniques to help understand:

- How weak passwords are exploited
- The effectiveness of dictionary vs brute-force attacks
- Real-world limitations of password-based security
- Incident response and forensic password analysis

**Target users:**
- Cybersecurity students
- Digital forensics learners
- Blue-team / defensive security training environments

---

## 🚀 Features

- Hash password auditing:
  - MD5
  - SHA-1
  - SHA-224
  - SHA-256
  - SHA-512
  - bcrypt (cryptographically correct verification)

- Encrypted file password testing:
  - PDF
  - ZIP
  - Microsoft Office files (`.docx`, `.xlsx`)

- Attack modes:
  - Dictionary Attack
  - Mask Attack
  - Hybrid Attack (Dictionary + Mask)
  - Brute Force Attack

- Performance & safety:
  - Memory-safe wordlist streaming (rockyou-compatible)
  - Multiprocessing support
  - Progress tracking
  - Attempt limits to prevent runaway execution

---

## 📂 Project Structure

```
password-audit-tool/
│
├── password_audit_tool.py
├── requirements.txt
├── LICENSE
└── README.md
```

---

## 📦 Installation

### 1️⃣ Clone the repository
```bash
git clone https://github.com/bhargavram-sec/password-audit-tool.git
cd password-audit-tool
```

### 2️⃣ Install dependencies
```bash
pip install -r requirements.txt
```

### ▶️ Usage
```bash
python password_audit_tool.py
```

You will be guided interactively to:
1. Confirm authorization  
2. Select target type (hash or file)  
3. Choose attack mode  
4. Provide wordlist path (if required)  
5. Configure attack parameters  

## 📌 Wordlists

This tool supports external wordlists such as **rockyou.txt**.

Due to size and licensing considerations, wordlists are not included in this repository.  
Users must supply their own wordlist path when running the tool.

---

## 🔐 Security Design Notes

- bcrypt verification uses `bcrypt.checkpw()` (no insecure re-hashing)
- Large wordlists are streamed line-by-line to avoid memory exhaustion
- Explicit user confirmation before attack execution
- No hardcoded paths or bundled wordlists
- Designed to avoid accidental misuse

---

## 🎯 Learning Outcomes

Through this project, I learned:

- Practical password attack methodologies
- Limitations of brute-force and dictionary attacks
- Secure handling of sensitive data
- Ethical boundaries in offensive security
- Python performance optimization techniques

---

## 🚧 Future Enhancements

- GPU acceleration support
- Integration with Have I Been Pwned API
- Web-based dashboard
- Password policy compliance scoring

---

## 📜 License

This project is licensed under the **MIT License**.  
See the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Bhargav Ram**  
Cybersecurity Student  

---

🔎 This project is part of a cybersecurity learning portfolio and is not intended for malicious use.

---
