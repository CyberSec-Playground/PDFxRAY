import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import os
import re
import hashlib
import struct

try:
    from pypdf import PdfReader
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# File hash helpers
# ─────────────────────────────────────────────────────────────────────────────

def compute_file_hashes(path: str) -> dict:
    algorithms = {
        "MD5":     hashlib.md5(),
        "SHA-1":   hashlib.sha1(),
        "SHA-256": hashlib.sha256(),
        "SHA-512": hashlib.sha512(),
    }
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            for h in algorithms.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in algorithms.items()}


# ─────────────────────────────────────────────────────────────────────────────
# PDF encryption hash extraction
# ─────────────────────────────────────────────────────────────────────────────

def _parse_hex_or_literal(raw: bytes) -> bytes | None:
    """Parse a PDF string token — either <hexhex> or (literal)."""
    raw = raw.strip()
    if raw.startswith(b"<") and raw.endswith(b">"):
        hex_str = raw[1:-1].replace(b" ", b"").replace(b"\n", b"")
        try:
            return bytes.fromhex(hex_str.decode("ascii"))
        except Exception:
            return None
    if raw.startswith(b"(") and raw.endswith(b")"):
        return raw[1:-1]
    return None


def extract_pdf_encryption_info(path: str) -> dict:
    """
    Parse the /Encrypt dictionary from the raw PDF bytes and return
    all relevant fields needed to build Hashcat/JtR hashes.

    Supports PDF 1.x (RC4/AES-128) and PDF 2.0 (AES-256).
    """
    with open(path, "rb") as f:
        data = f.read()

    result = {
        "encrypted":   False,
        "filter":      None,
        "revision":    None,
        "version":     None,
        "key_length":  None,
        "permissions": None,
        "O_hash":      None,   # /O  — owner password verifier
        "U_hash":      None,   # /U  — user password verifier
        "OE_hash":     None,   # /OE — owner key (PDF ≥ 1.7 R5/R6)
        "UE_hash":     None,   # /UE — user key  (PDF ≥ 1.7 R5/R6)
        "encrypt_metadata": True,
        "file_id":     None,
        "hashcat_hash": None,
        "error":       None,
    }

    # ── locate /Encrypt dictionary ────────────────────────────────
    enc_match = re.search(rb"/Encrypt\s*<<(.*?)>>", data, re.DOTALL)
    if not enc_match:
        # Try indirect object reference form: /Encrypt N N R
        ref_match = re.search(rb"/Encrypt\s+(\d+)\s+(\d+)\s+R", data)
        if ref_match:
            obj_num = ref_match.group(1).decode()
            obj_pat = re.compile(
                rb"\b" + obj_num.encode() + rb"\s+\d+\s+obj\s*<<(.*?)>>",
                re.DOTALL
            )
            obj_match = obj_pat.search(data)
            if obj_match:
                enc_match = obj_match
        if not enc_match:
            return result

    result["encrypted"] = True
    enc_block = enc_match.group(1)

    def get_int(key: str) -> int | None:
        m = re.search(key.encode() + rb"\s+(-?\d+)", enc_block)
        return int(m.group(1)) if m else None

    def get_name(key: str) -> str | None:
        m = re.search(key.encode() + rb"\s*/(\w+)", enc_block)
        return m.group(1).decode() if m else None

    def get_string(key: str) -> bytes | None:
        # Match <hex> or (literal) after key
        m = re.search(key.encode() + rb"\s*(<[^>]*>|\([^)]*\))", enc_block, re.DOTALL)
        if m:
            return _parse_hex_or_literal(m.group(1))
        return None

    result["filter"]      = get_name("/Filter")
    result["revision"]    = get_int("/R")
    result["version"]     = get_int("/V")
    result["key_length"]  = get_int("/Length") or (40 if (result["revision"] or 2) <= 2 else 128)
    result["permissions"] = get_int("/P")

    O  = get_string("/O")
    U  = get_string("/U")
    OE = get_string("/OE")
    UE = get_string("/UE")

    result["O_hash"]  = O.hex()  if O  else None
    result["U_hash"]  = U.hex()  if U  else None
    result["OE_hash"] = OE.hex() if OE else None
    result["UE_hash"] = UE.hex() if UE else None

    em_match = re.search(rb"/EncryptMetadata\s*/(\w+)", enc_block)
    result["encrypt_metadata"] = (em_match.group(1) != b"false") if em_match else True

    # ── extract first /ID from trailer ───────────────────────────
    id_match = re.search(rb"/ID\s*\[\s*(<[^>]+>)", data)
    if id_match:
        raw_id = _parse_hex_or_literal(id_match.group(1))
        result["file_id"] = raw_id.hex() if raw_id else None

    # ── build Hashcat-compatible hash string ─────────────────────
    result["hashcat_hash"] = _build_hashcat_hash(result)

    return result


def _build_hashcat_hash(info: dict) -> str | None:
    """
    Build the Hashcat hash string for the detected PDF revision.

    Format reference:
      R2/R3  → $pdf$1*2*<keybits>*<P>*<encmeta>*<idlen>*<id>*<Olen>*<O>*<Ulen>*<U>
      R4     → $pdf$2*3*128*<P>*<encmeta>*<idlen>*<id>*<Olen>*<O>*<Ulen>*<U>
      R5     → $pdf$5*5*256*<P>*<encmeta>*<idlen>*<id>*<Olen>*<O>*<Ulen>*<U>*<OElen>*<OE>*<UElen>*<UE>
      R6     → $pdf$6*6*256*...  (same as R5)
    """
    rev  = info.get("revision")
    O    = info.get("O_hash")
    U    = info.get("U_hash")
    OE   = info.get("OE_hash")
    UE   = info.get("UE_hash")
    P    = info.get("permissions", -4)
    fid  = info.get("file_id") or ("00" * 16)
    bits = info.get("key_length") or 128
    em   = 1 if info.get("encrypt_metadata", True) else 0

    if not O or not U:
        return None

    if rev in (2, 3):
        ver = 1
        return (f"$pdf${ver}*{rev}*{bits}*{P}*{em}"
                f"*{len(fid)//2}*{fid}"
                f"*{len(O)//2}*{O}"
                f"*{len(U)//2}*{U}")
    elif rev == 4:
        ver = 2
        return (f"$pdf${ver}*{rev}*{bits}*{P}*{em}"
                f"*{len(fid)//2}*{fid}"
                f"*{len(O)//2}*{O}"
                f"*{len(U)//2}*{U}")
    elif rev in (5, 6):
        ver = rev  # Hashcat uses $pdf$5 and $pdf$6
        oe_part = f"*{len(OE)//2}*{OE}" if OE else "*0*"
        ue_part = f"*{len(UE)//2}*{UE}" if UE else "*0*"
        return (f"$pdf${ver}*{rev}*256*{P}*{em}"
                f"*{len(fid)//2}*{fid}"
                f"*{len(O)//2}*{O}"
                f"*{len(U)//2}*{U}"
                f"{oe_part}{ue_part}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# GUI
# ─────────────────────────────────────────────────────────────────────────────

class PDFSelectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF Selector & Hash Extractor")
        self.root.geometry("740x860")
        self.root.resizable(True, True)
        self.root.configure(bg="#f5f5f5")
        self.current_path = None
        self.selected_path = tk.StringVar(value="No file selected")
        self._enc_info = {}
        self._build_ui()

    # ── UI ────────────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        header = tk.Frame(self.root, bg="#1a73e8")
        header.pack(fill="x")
        tk.Label(header, text="📄  PDF Selector & Hash Extractor",
                 font=("Segoe UI", 15, "bold"), fg="white", bg="#1a73e8"
                 ).pack(side="left", padx=20, pady=12)

        # File picker
        pf = tk.Frame(self.root, bg="#f5f5f5", pady=14)
        pf.pack(fill="x", padx=20)
        tk.Label(pf, textvariable=self.selected_path,
                 font=("Segoe UI", 10), fg="#444", bg="#ffffff",
                 anchor="w", padx=10, relief="solid", bd=1,
                 wraplength=460, justify="left"
                 ).pack(side="left", ipady=6, fill="x", expand=True)
        tk.Button(pf, text="Browse…", font=("Segoe UI", 10, "bold"),
                  bg="#1a73e8", fg="white", activebackground="#1558b0",
                  relief="flat", cursor="hand2", padx=14, pady=6,
                  command=self.select_pdf
                  ).pack(side="left", padx=(10, 0))

        # File Info
        self._build_info_panel()

        # File Hashes
        self._build_hash_panel()

        # Encryption / Password Hash
        self._build_enc_panel()

        # Buttons
        self._build_buttons()

        # Status
        self.status_var = tk.StringVar(value="Ready — click Browse to select a PDF.")
        tk.Label(self.root, textvariable=self.status_var,
                 font=("Segoe UI", 9), fg="#666", bg="#e8e8e8",
                 anchor="w", padx=10, relief="sunken"
                 ).pack(side="bottom", fill="x")

    def _build_info_panel(self):
        frm = tk.LabelFrame(self.root, text=" File Info ",
                            font=("Segoe UI", 10, "bold"),
                            bg="#f5f5f5", fg="#555", padx=14, pady=8)
        frm.pack(fill="x", padx=20, pady=(0, 8))
        self.info_vars = {}
        for i, (lbl, key) in enumerate([
            ("File name", "name"), ("Location", "dir"),
            ("Size", "size"), ("Pages", "pages"),
            ("Title", "title"), ("Author", "author"),
        ]):
            tk.Label(frm, text=f"{lbl}:", font=("Segoe UI", 10, "bold"),
                     bg="#f5f5f5", fg="#333", anchor="w", width=12
                     ).grid(row=i, column=0, sticky="w", pady=2)
            var = tk.StringVar(value="—")
            self.info_vars[key] = var
            tk.Label(frm, textvariable=var, font=("Segoe UI", 10),
                     bg="#f5f5f5", fg="#222", anchor="w",
                     wraplength=480, justify="left"
                     ).grid(row=i, column=1, sticky="w", padx=(10, 0), pady=2)
        frm.columnconfigure(1, weight=1)

    def _build_hash_panel(self):
        frm = tk.LabelFrame(self.root, text=" File Hashes ",
                            font=("Segoe UI", 10, "bold"),
                            bg="#f5f5f5", fg="#555", padx=14, pady=8)
        frm.pack(fill="x", padx=20, pady=(0, 8))
        self.hash_vars = {}
        for i, algo in enumerate(["MD5", "SHA-1", "SHA-256", "SHA-512"]):
            tk.Label(frm, text=f"{algo}:", font=("Segoe UI", 10, "bold"),
                     bg="#f5f5f5", fg="#333", anchor="w", width=8
                     ).grid(row=i, column=0, sticky="w", pady=3)
            var = tk.StringVar(value="—")
            self.hash_vars[algo] = var
            tk.Entry(frm, textvariable=var, font=("Courier New", 9),
                     fg="#1a1a2e", bg="#eef2ff", relief="solid", bd=1,
                     state="readonly", readonlybackground="#eef2ff"
                     ).grid(row=i, column=1, sticky="ew", padx=(10, 6), pady=3, ipady=3)
            tk.Button(frm, text="Copy", font=("Segoe UI", 9),
                      bg="#6c63ff", fg="white", activebackground="#4b45c4",
                      relief="flat", cursor="hand2", padx=8, pady=2,
                      command=lambda v=var, a=algo: self._copy_to_clipboard(v.get(), a)
                      ).grid(row=i, column=2, pady=3)
        frm.columnconfigure(1, weight=1)

    def _build_enc_panel(self):
        frm = tk.LabelFrame(self.root, text=" PDF Encryption / Password Hash ",
                            font=("Segoe UI", 10, "bold"),
                            bg="#f5f5f5", fg="#555", padx=14, pady=8)
        frm.pack(fill="x", padx=20, pady=(0, 8))

        # Status row
        self.enc_vars = {}
        for i, (lbl, key) in enumerate([
            ("Encrypted",   "enc_status"),
            ("Filter",      "enc_filter"),
            ("Revision",    "enc_revision"),
            ("Key length",  "enc_keybits"),
            ("Permissions", "enc_perms"),
        ]):
            tk.Label(frm, text=f"{lbl}:", font=("Segoe UI", 10, "bold"),
                     bg="#f5f5f5", fg="#333", anchor="w", width=13
                     ).grid(row=i, column=0, sticky="w", pady=2)
            var = tk.StringVar(value="—")
            self.enc_vars[key] = var
            tk.Label(frm, textvariable=var, font=("Segoe UI", 10),
                     bg="#f5f5f5", fg="#222", anchor="w"
                     ).grid(row=i, column=1, sticky="w", padx=(10, 0), pady=2)

        # Raw hash fields (/O, /U, /OE, /UE)
        row_base = 5
        for j, (lbl, key) in enumerate([
            ("/O  (Owner verifier)", "O_hash"),
            ("/U  (User verifier)",  "U_hash"),
            ("/OE (Owner key enc)",  "OE_hash"),
            ("/UE (User key enc)",   "UE_hash"),
        ]):
            ri = row_base + j
            tk.Label(frm, text=f"{lbl}:", font=("Segoe UI", 9, "bold"),
                     bg="#f5f5f5", fg="#555", anchor="w", width=22
                     ).grid(row=ri, column=0, sticky="w", pady=2)
            var = tk.StringVar(value="—")
            self.enc_vars[key] = var
            tk.Entry(frm, textvariable=var, font=("Courier New", 8),
                     fg="#1a1a2e", bg="#fff8e1", relief="solid", bd=1,
                     state="readonly", readonlybackground="#fff8e1"
                     ).grid(row=ri, column=1, sticky="ew", padx=(6, 6), pady=2, ipady=3)
            tk.Button(frm, text="Copy", font=("Segoe UI", 9),
                      bg="#f29900", fg="white", activebackground="#c07a00",
                      relief="flat", cursor="hand2", padx=6, pady=1,
                      command=lambda v=var, a=lbl: self._copy_to_clipboard(v.get(), a)
                      ).grid(row=ri, column=2, pady=2)

        # Hashcat hash
        hc_row = row_base + 4
        tk.Label(frm, text="Hashcat hash:", font=("Segoe UI", 9, "bold"),
                 bg="#f5f5f5", fg="#333", anchor="w", width=22
                 ).grid(row=hc_row, column=0, sticky="nw", pady=(6, 2))

        self.hashcat_text = tk.Text(frm, font=("Courier New", 8),
                                    fg="#0d3349", bg="#e8f5e9",
                                    relief="solid", bd=1,
                                    height=3, wrap="char", state="disabled")
        self.hashcat_text.grid(row=hc_row, column=1, sticky="ew",
                               padx=(6, 6), pady=(6, 2), ipady=2)
        tk.Button(frm, text="Copy", font=("Segoe UI", 9),
                  bg="#34a853", fg="white", activebackground="#267d3d",
                  relief="flat", cursor="hand2", padx=6, pady=1,
                  command=self._copy_hashcat
                  ).grid(row=hc_row, column=2, sticky="n", pady=(6, 2))

        frm.columnconfigure(1, weight=1)

    def _build_buttons(self):
        frm = tk.Frame(self.root, bg="#f5f5f5")
        frm.pack(fill="x", padx=20, pady=(0, 10))

        self.open_btn = tk.Button(frm, text="Open in Default Viewer",
                                   font=("Segoe UI", 10),
                                   bg="#34a853", fg="white",
                                   activebackground="#267d3d",
                                   relief="flat", cursor="hand2",
                                   padx=14, pady=6, state="disabled",
                                   command=self.open_pdf)
        self.open_btn.pack(side="left")

        self.export_btn = tk.Button(frm, text="Export All Hashes…",
                                     font=("Segoe UI", 10),
                                     bg="#f29900", fg="white",
                                     activebackground="#c07a00",
                                     relief="flat", cursor="hand2",
                                     padx=14, pady=6, state="disabled",
                                     command=self.export_hashes)
        self.export_btn.pack(side="left", padx=(10, 0))

        self.clear_btn = tk.Button(frm, text="Clear",
                                    font=("Segoe UI", 10),
                                    bg="#ea4335", fg="white",
                                    activebackground="#b5302a",
                                    relief="flat", cursor="hand2",
                                    padx=14, pady=6, state="disabled",
                                    command=self.clear_selection)
        self.clear_btn.pack(side="left", padx=(10, 0))

    # ── Handlers ─────────────────────────────────────────────────

    def select_pdf(self):
        path = filedialog.askopenfilename(
            title="Select a PDF file",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if not path:
            return
        self.current_path = path
        self.selected_path.set(path)
        self.status_var.set("Analysing file…")
        self.root.update_idletasks()

        self._populate_info(path)
        self._populate_file_hashes(path)
        self._populate_enc_info(path)

        self.open_btn.config(state="normal")
        self.export_btn.config(state="normal")
        self.clear_btn.config(state="normal")
        self.status_var.set(f"Done — {os.path.basename(path)}")

    def _populate_info(self, path):
        stat = os.stat(path)
        kb = stat.st_size / 1024
        self.info_vars["name"].set(os.path.basename(path))
        self.info_vars["dir"].set(os.path.dirname(path))
        self.info_vars["size"].set(f"{kb:.1f} KB" if kb < 1024 else f"{kb/1024:.2f} MB")
        if PYPDF_AVAILABLE:
            try:
                reader = PdfReader(path)
                self.info_vars["pages"].set(str(len(reader.pages)))
                meta = reader.metadata or {}
                self.info_vars["title"].set(meta.title or "—")
                self.info_vars["author"].set(meta.author or "—")
            except Exception:
                for k in ("pages", "title", "author"):
                    self.info_vars[k].set("—")
        else:
            self.info_vars["pages"].set("install pypdf")
            self.info_vars["title"].set("—")
            self.info_vars["author"].set("—")

    def _populate_file_hashes(self, path):
        try:
            for algo, digest in compute_file_hashes(path).items():
                self.hash_vars[algo].set(digest)
        except Exception as e:
            for v in self.hash_vars.values():
                v.set("Error")
            messagebox.showerror("Hash Error", str(e))

    def _populate_enc_info(self, path):
        info = extract_pdf_encryption_info(path)
        self._enc_info = info

        if info.get("error"):
            self.enc_vars["enc_status"].set(f"Parse error: {info['error']}")
            return

        if not info["encrypted"]:
            self.enc_vars["enc_status"].set("Not encrypted")
            for k in ("enc_filter","enc_revision","enc_keybits","enc_perms",
                      "O_hash","U_hash","OE_hash","UE_hash"):
                self.enc_vars[k].set("N/A")
            self._set_hashcat_text("PDF is not encrypted — no password hash present.")
            return

        rev = info["revision"] or "?"
        self.enc_vars["enc_status"].set("✅  Yes")
        self.enc_vars["enc_filter"].set(info["filter"] or "Standard")
        self.enc_vars["enc_revision"].set(
            f"{rev}  →  " + {
                2: "RC4-40",  3: "RC4-128", 4: "AES-128 / RC4-128",
                5: "AES-256 (R5)", 6: "AES-256 (R6)"
            }.get(rev, "Unknown")
        )
        self.enc_vars["enc_keybits"].set(
            f"{info['key_length']} bits" if info["key_length"] else "—"
        )
        self.enc_vars["enc_perms"].set(str(info["permissions"]) if info["permissions"] is not None else "—")

        for field in ("O_hash", "U_hash", "OE_hash", "UE_hash"):
            self.enc_vars[field].set(info.get(field) or "—")

        hc = info.get("hashcat_hash") or "Could not build Hashcat hash (missing fields)."
        self._set_hashcat_text(hc)

    def _set_hashcat_text(self, text: str):
        self.hashcat_text.config(state="normal")
        self.hashcat_text.delete("1.0", "end")
        self.hashcat_text.insert("1.0", text)
        self.hashcat_text.config(state="disabled")

    def _copy_to_clipboard(self, value: str, label: str):
        if value and value not in ("—", "N/A", "Error"):
            self.root.clipboard_clear()
            self.root.clipboard_append(value)
            self.status_var.set(f"Copied {label} to clipboard.")

    def _copy_hashcat(self):
        text = self.hashcat_text.get("1.0", "end").strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.status_var.set("Hashcat hash copied to clipboard.")

    def open_pdf(self):
        try:
            import subprocess, sys
            if sys.platform.startswith("win"):
                os.startfile(self.current_path)
            elif sys.platform == "darwin":
                subprocess.call(["open", self.current_path])
            else:
                subprocess.call(["xdg-open", self.current_path])
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def export_hashes(self):
        if not self.current_path:
            return
        base = os.path.splitext(os.path.basename(self.current_path))[0]
        save_path = filedialog.asksaveasfilename(
            title="Save hashes as…",
            defaultextension=".txt",
            initialfile=f"{base}_hashes.txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not save_path:
            return
        try:
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(f"File : {self.current_path}\n")
                f.write(f"Size : {self.info_vars['size'].get()}\n")
                f.write("=" * 80 + "\n\n")

                f.write("[File Hashes]\n")
                for algo, var in self.hash_vars.items():
                    f.write(f"  {algo:<10}: {var.get()}\n")

                f.write("\n[PDF Encryption]\n")
                info = self._enc_info
                f.write(f"  Encrypted  : {info.get('encrypted', False)}\n")
                if info.get("encrypted"):
                    f.write(f"  Filter     : {info.get('filter')}\n")
                    f.write(f"  Revision   : {info.get('revision')}\n")
                    f.write(f"  Key length : {info.get('key_length')} bits\n")
                    f.write(f"  Permissions: {info.get('permissions')}\n")
                    f.write(f"  File ID    : {info.get('file_id')}\n")
                    f.write(f"  /O         : {info.get('O_hash')}\n")
                    f.write(f"  /U         : {info.get('U_hash')}\n")
                    f.write(f"  /OE        : {info.get('OE_hash')}\n")
                    f.write(f"  /UE        : {info.get('UE_hash')}\n")
                    f.write(f"\n[Hashcat Hash]\n  {info.get('hashcat_hash')}\n")

            self.status_var.set(f"Exported → {os.path.basename(save_path)}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def clear_selection(self):
        self.current_path = None
        self._enc_info = {}
        self.selected_path.set("No file selected")
        for v in self.info_vars.values():
            v.set("—")
        for v in self.hash_vars.values():
            v.set("—")
        for v in self.enc_vars.values():
            v.set("—")
        self._set_hashcat_text("")
        self.open_btn.config(state="disabled")
        self.export_btn.config(state="disabled")
        self.clear_btn.config(state="disabled")
        self.status_var.set("Ready — click Browse to select a PDF.")


def main():
    root = tk.Tk()
    PDFSelectorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()