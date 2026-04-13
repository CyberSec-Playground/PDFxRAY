# 🔍 PDFxRay

> A desktop forensics tool for PDF file analysis — inspect metadata, compute file hashes, and extract encryption password hashes in a clean GUI.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)
![GUI](https://img.shields.io/badge/GUI-Tkinter-orange)
![License](https://img.shields.io/badge/License-MIT-green)

---

## ✨ Features

| Feature | Details |
|---|---|
| 📂 **PDF File Picker** | Native file dialog filtered to `.pdf` files |
| 📋 **File Metadata** | Name, location, size, page count, title, author |
| 🔐 **File Hashes** | MD5, SHA-1, SHA-256, SHA-512 of the raw file bytes |
| 🔒 **Encryption Detection** | Detects if PDF is encrypted and extracts full encryption info |
| 🗝️ **Password Hash Extraction** | Extracts `/O`, `/U`, `/OE`, `/UE` fields from the PDF encrypt dictionary |
| ⚙️ **Hashcat Hash Builder** | Auto-generates a ready-to-use `$pdf$...` Hashcat hash string |
| 📤 **Export** | Save all hashes + encryption details to a `.txt` report |
| 📋 **One-click Copy** | Copy any individual hash to clipboard instantly |

---


## 🚀 Getting Started

### Prerequisites

- Python 3.10 or higher
- `pypdf` (optional — for page count and metadata)

### Install dependencies

```bash
pip install pypdf
```

### Run from source

```bash
python pdf_selector.py
```

---

## 📦 Building an EXE with PyInstaller

PDFxRay can be compiled into a standalone `.exe` with no Python installation required on the target machine.

### 1. Install PyInstaller

```bash
pip install pyinstaller
```

### 2. Build (single file, no console window)

```bash
pyinstaller --onefile --windowed --name PDFxRay pdf_selector.py
```

| Flag | Purpose |
|---|---|
| `--onefile` | Bundle everything into a single `.exe` |
| `--windowed` | Suppress the black console window (GUI only) |
| `--name PDFxRay` | Set the output executable name |

### 3. Optional — add a custom icon

```bash
pyinstaller --onefile --windowed --name PDFxRay --icon=icon.ico pdf_selector.py
```

> 💡 Use a `.ico` file on Windows. Convert PNG → ICO at [convertico.com](https://convertico.com) or use `Pillow`:
> ```bash
> pip install pillow
> python -c "from PIL import Image; Image.open('icon.png').save('icon.ico')"
> ```

### 4. Find your executable

```
dist/
└── PDFxRay.exe   ← your portable executable
```

### 5. Troubleshoot missing modules

If `pypdf` is not bundled automatically:

```bash
pyinstaller --onefile --windowed --name PDFxRay --hidden-import=pypdf pdf_selector.py
```

---

## 🔐 Encryption Hash Details

PDFxRay parses the raw PDF binary to extract the encryption dictionary fields used for password verification. These are the same values tools like **Hashcat** and **John the Ripper** use.

### Supported PDF Revisions

| Revision | Algorithm | Hashcat Mode |
|---|---|---|
| R2 | RC4-40 | `-m 10400` |
| R3 | RC4-128 | `-m 10410` |
| R4 | AES-128 / RC4-128 | `-m 10420` |
| R5 | AES-256 (SHA-256) | `-m 10500` |
| R6 | AES-256 (SHA-512) | `-m 10600` |

### Extracted Fields

| Field | Description |
|---|---|
| `/O` | Owner password verifier (32–48 bytes) |
| `/U` | User password verifier (32–48 bytes) |
| `/OE` | Owner key encrypted with password (AES-256 only) |
| `/UE` | User key encrypted with password (AES-256 only) |

### Using the Hashcat hash with your wordlist

PDFxRay automatically builds the `$pdf$...` string. Copy it, save to `hash.txt`, then run:

```bash
# AES-256 R5 (most modern PDFs)
hashcat -m 10500 -a 0 hash.txt wordlist.txt

# AES-256 R6
hashcat -m 10600 -a 0 hash.txt wordlist.txt

# RC4-128 R3/R4
hashcat -m 10410 -a 0 hash.txt wordlist.txt

# RC4-40 R2
hashcat -m 10400 -a 0 hash.txt wordlist.txt
```

---

## 🗂️ Project Structure

```
PDFxRay/
├── pdf_selector.py     # Main application
├── README.md           # This file
└── icon.ico            # (Optional) app icon for PyInstaller
```

---

## 🛠️ Built With

- [Python](https://python.org) — core language
- [Tkinter](https://docs.python.org/3/library/tkinter.html) — GUI framework (stdlib)
- [hashlib](https://docs.python.org/3/library/hashlib.html) — file hashing (stdlib)
- [pypdf](https://pypdf.readthedocs.io/) — PDF metadata (optional)
- [PyInstaller](https://pyinstaller.org/) — EXE packaging

---

## ⚖️ Legal Disclaimer

PDFxRay is intended for **lawful use only** — such as analysing PDF files you own or have explicit permission to inspect. The authors accept no responsibility for misuse of this tool.

---

## 📄 License

MIT © 2025 — free to use, modify, and distribute.
