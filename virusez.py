import os
import re
import json
import hashlib
import secrets
import zipfile
import tarfile
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime

APP = "VirusEz"
BG = "#e5f3e9"
PANEL = "#f4faf5"
BLUE = "#25834d"
DARK = "#14532d"
TEXT = "#183b28"
MUTED = "#668071"
GREEN = "#36a663"
YELLOW = "#e6b65f"
RED = "#c95b67"
DB_PATH = os.path.join(os.path.expanduser("~"), ".virusez_accounts.json")

# Heuristic indicators only. A match is not proof that a file is malicious.
PATTERNS = [
    (b"powershell -enc", "Encoded PowerShell command", "High"),
    (b"frombase64string", "PowerShell Base64 decoding", "Medium"),
    (b"wscript.shell", "Windows Script Host automation", "Medium"),
    (b"writeprocessmemory", "Process memory writing API", "High"),
    (b"createremotethread", "Remote thread creation API", "High"),
    (b"virtualalloc", "Memory allocation API", "Medium"),
    (b"urldownloadtofile", "URL download API", "Medium"),
    (b"bitsadmin", "BITS command reference", "Medium"),
    (b"rundll32", "Rundll32 execution reference", "Medium"),
    (b"disabledefender", "Possible security-disabling string", "High"),
    (b"discord.com/api/webhooks", "Discord webhook reference", "Medium"),
    (b"discordapp.com/api/webhooks", "Discord webhook reference", "Medium"),
    (b"reg add", "Registry modification command", "Low"),
]

def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 bytes.fromhex(salt), 180_000).hex()
    return salt, digest

def load_accounts():
    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}

def save_accounts(accounts):
    temp = DB_PATH + ".tmp"
    with open(temp, "w", encoding="utf-8") as f:
        json.dump(accounts, f)
    os.replace(temp, DB_PATH)

class VirusEz:
    def __init__(self, root):
        self.root = root
        self.root.title("VirusEz - File Protection Center")
        self.root.geometry("900x690")
        self.root.minsize(780, 620)
        self.root.configure(bg=BG)
        self.path = None
        self.current_user = None
        self.accounts = load_accounts()
        self.file_items = []
        self.findings = []
        self.build_login()

    def clear_window(self):
        for child in self.root.winfo_children():
            child.destroy()

    def header(self, subtitle="FILE PROTECTION CENTER"):
        banner = tk.Frame(self.root, bg=DARK, height=76)
        banner.pack(fill="x")
        banner.pack_propagate(False)
        logo = tk.Canvas(banner, width=48, height=48, bg=DARK, highlightthickness=0)
        logo.pack(side="left", padx=(18, 10), pady=12)
        logo.create_oval(3, 3, 45, 45, fill="#edf5fc", outline="#a8c1d9", width=2)
        logo.create_text(24, 23, text="V", fill=BLUE, font=("Arial", 22, "bold"))
        brand = tk.Frame(banner, bg=DARK)
        brand.pack(side="left", pady=11)
        tk.Label(brand, text="VirusEz", bg=DARK, fg="white",
                 font=("Arial", 22, "bold")).pack(anchor="w")
        tk.Label(brand, text=subtitle, bg=DARK, fg="#c8ead2",
                 font=("Arial", 8, "bold")).pack(anchor="w")
        if self.current_user:
            tk.Label(banner, text=f"Signed in: {self.current_user}", bg=DARK, fg="#dcfce7",
                     font=("Arial", 9, "bold")).pack(side="right", padx=18)

    def build_login(self):
        self.clear_window()
        self.header("WELCOME  /  ACCOUNT ACCESS")
        outer = tk.Frame(self.root, bg=BG, padx=25, pady=24)
        outer.pack(fill="both", expand=True)
        card = tk.Frame(outer, bg=PANEL, highlightbackground="#a8cdb2", highlightthickness=1)
        card.place(relx=.5, rely=.46, anchor="center", width=390, height=390)

        tk.Label(card, text="Welcome to VirusEz", bg=PANEL, fg=TEXT,
                 font=("Arial", 18, "bold")).pack(pady=(28, 5))
        tk.Label(card, text="Sign in or create a local account", bg=PANEL, fg=MUTED,
                 font=("Arial", 9)).pack(pady=(0, 20))

        tk.Label(card, text="USERNAME", bg=PANEL, fg=BLUE,
                 font=("Arial", 8, "bold")).pack(anchor="w", padx=35)
        self.username_entry = tk.Entry(card, font=("Arial", 11), relief="solid", bd=1)
        self.username_entry.pack(fill="x", padx=35, ipady=7, pady=(5, 13))

        tk.Label(card, text="PASSWORD", bg=PANEL, fg=BLUE,
                 font=("Arial", 8, "bold")).pack(anchor="w", padx=35)
        self.password_entry = tk.Entry(card, show="●", font=("Arial", 11), relief="solid", bd=1)
        self.password_entry.pack(fill="x", padx=35, ipady=7, pady=(5, 18))
        self.password_entry.bind("<Return>", lambda event: self.login())

        row = tk.Frame(card, bg=PANEL)
        row.pack(fill="x", padx=35)
        ttk.Button(row, text="Log in", command=self.login).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Sign up", command=self.signup).pack(side="left", fill="x", expand=True, padx=(9, 0))

        tk.Label(card, text="Accounts are stored locally on this computer.\nUse a unique password, not your main account password.",
                 bg=PANEL, fg=MUTED, font=("Arial", 8), justify="center").pack(pady=20)

        style = ttk.Style()
        try:
            style.theme_use("vista")
        except tk.TclError:
            style.theme_use("clam")
        style.configure("TButton", font=("Arial", 9), padding=(10, 7))
        style.configure("Horizontal.TProgressbar", troughcolor="#d8e9dc", background="#2e9b58")

    def credentials(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,24}", username):
            messagebox.showwarning("VirusEz", "Username must be 3–24 characters: letters, numbers, . _ -")
            return None, None
        if len(password) < 6:
            messagebox.showwarning("VirusEz", "Password must be at least 6 characters.")
            return None, None
        return username, password

    def signup(self):
        username, password = self.credentials()
        if username is None:
            return
        key = username.casefold()
        if key in self.accounts:
            messagebox.showerror("VirusEz", "That username already exists.")
            return
        salt, digest = hash_password(password)
        self.accounts[key] = {"username": username, "salt": salt, "hash": digest}
        try:
            save_accounts(self.accounts)
        except OSError as exc:
            messagebox.showerror("VirusEz", f"Could not save local account:\n{exc}")
            return
        self.current_user = username
        self.build_main()

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        record = self.accounts.get(username.casefold())
        if not record:
            messagebox.showerror("VirusEz", "Account not found. Sign up first.")
            return
        _, digest = hash_password(password, record["salt"])
        if not secrets.compare_digest(digest, record["hash"]):
            messagebox.showerror("VirusEz", "Incorrect password.")
            return
        self.current_user = record["username"]
        self.build_main()

    def logout(self):
        self.current_user = None
        self.path = None
        self.build_login()

    def build_main(self):
        self.clear_window()
        self.header("FILE PROTECTION CENTER  /  SCANNER")
        body = tk.Frame(self.root, bg=BG, padx=18, pady=14)
        body.pack(fill="both", expand=True)

        intro = tk.Frame(body, bg=PANEL, highlightbackground="#a8cdb2", highlightthickness=1)
        intro.pack(fill="x")
        tk.Label(intro, text="File scanner", bg=PANEL, fg=TEXT,
                 font=("Arial", 13, "bold")).pack(anchor="w", padx=14, pady=(10, 2))
        tk.Label(intro, text="Select a file or folder, scan its contents, and review suspicious items.",
                 bg=PANEL, fg=MUTED, font=("Arial", 9)).pack(anchor="w", padx=14, pady=(0, 10))

        select = tk.Frame(body, bg=PANEL, highlightbackground="#a8cdb2", highlightthickness=1)
        select.pack(fill="x", pady=(10, 0))
        tk.Label(select, text="SELECTED FILE / FOLDER", bg=PANEL, fg=BLUE,
                 font=("Arial", 8, "bold")).pack(anchor="w", padx=12, pady=(9, 3))
        line = tk.Frame(select, bg=PANEL)
        line.pack(fill="x", padx=12, pady=(0, 10))
        self.file_label = tk.Label(line, text="No file or folder selected", bg="white", fg="#718096",
                                   anchor="w", relief="sunken", bd=1, padx=8, pady=7,
                                   font=("Arial", 9))
        self.file_label.pack(side="left", fill="x", expand=True)
        ttk.Button(line, text="Insert file...", command=self.choose_file).pack(side="left", padx=(7, 0))
        ttk.Button(line, text="Insert folder...", command=self.choose_folder).pack(side="left", padx=(7, 0))

        # Main scan view: count ring on the left, report on the right.
        middle = tk.Frame(body, bg=BG)
        middle.pack(fill="both", expand=True, pady=10)
        left = tk.Frame(middle, bg=PANEL, width=230, highlightbackground="#a8cdb2", highlightthickness=1)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        tk.Label(left, text="FILE CONTENTS", bg=PANEL, fg=BLUE,
                 font=("Arial", 9, "bold")).pack(pady=(14, 3))
        self.gauge = tk.Canvas(left, width=176, height=176, bg=PANEL, highlightthickness=0)
        self.gauge.pack(pady=(2, 0))
        self.draw_gauge(0, 0, GREEN)
        self.gauge_caption = tk.Label(left, text="ITEMS FLAGGED", bg=PANEL, fg=MUTED,
                                      font=("Arial", 9, "bold"))
        self.gauge_caption.pack(pady=(0, 5))
        self.file_count_label = tk.Label(left, text="No file scanned", bg=PANEL, fg=MUTED,
                                         font=("Arial", 8))
        self.file_count_label.pack()
        self.scan_button = ttk.Button(left, text="Scan selected file", command=self.scan)
        self.scan_button.pack(fill="x", padx=15, pady=(17, 7))
        ttk.Button(left, text="Delete selected file", command=self.delete_file).pack(fill="x", padx=15)
        ttk.Button(left, text="Log out", command=self.logout).pack(fill="x", padx=15, pady=(7, 14))

        right = tk.Frame(middle, bg=PANEL, highlightbackground="#a8cdb2", highlightthickness=1)
        right.pack(side="left", fill="both", expand=True, padx=(10, 0))
        top = tk.Frame(right, bg="#dcefe2")
        top.pack(fill="x")
        tk.Label(top, text="DETECTED ITEMS / SCAN REPORT", bg="#dce8f5", fg=DARK,
                 font=("Arial", 9, "bold")).pack(anchor="w", padx=11, pady=9)
        self.report = tk.Text(right, bg="white", fg=TEXT, font=("Consolas", 9),
                              wrap="word", relief="flat", padx=10, pady=9, state="disabled")
        self.report.pack(fill="both", expand=True, padx=1, pady=1)
        self.report.tag_configure("bad", foreground=RED, font=("Arial", 9, "bold"))
        self.report.tag_configure("warn", foreground="#a96b14", font=("Arial", 9, "bold"))
        self.report.tag_configure("good", foreground="#287b4b", font=("Arial", 9, "bold"))
        self.report.tag_configure("muted", foreground=MUTED)
        self.write_report("Insert a file to begin.\n\nIf suspicious indicators are found, their names and severity will appear here.")

        footer = tk.Frame(body, bg=BG)
        footer.pack(fill="x")
        tk.Label(footer, text="VirusEz 1.1  |  Local file scan", bg=BG, fg=MUTED,
                 font=("Arial", 8)).pack(side="left")
        tk.Label(footer, text="Heuristic scanner — not a full antivirus", bg=BG, fg=MUTED,
                 font=("Arial", 8)).pack(side="right")

    def draw_gauge(self, flagged, total, color):
        self.gauge.delete("all")
        self.gauge.create_oval(19, 12, 157, 150, outline="#d9e4ed", width=11)
        if total:
            fraction = min(1.0, flagged / total)
            if fraction > 0:
                self.gauge.create_arc(19, 12, 157, 150, start=90, extent=-360*fraction,
                                      style="arc", outline=color, width=11)
            else:
                self.gauge.create_oval(19, 12, 157, 150, outline=GREEN, width=11)
        else:
            self.gauge.create_oval(19, 12, 157, 150, outline="#d9e4ed", width=11)
        self.gauge.create_text(88, 68, text=str(flagged), fill=color,
                               font=("Arial", 24))
        self.gauge.create_text(88, 96, text=f"/ {total}", fill=MUTED,
                               font=("Arial", 10))

    def choose_file(self):
        path = filedialog.askopenfilename(title="Insert a file to scan", filetypes=[("All files", "*.*")])
        if path:
            self.path = path
            self.file_label.config(text=path, fg=TEXT)
            self.draw_gauge(0, 0, GREEN)
            self.file_count_label.config(text="Ready to scan")
            self.write_report("Selected file:\n" + path + "\n\nClick “Scan selected file”.")

    def choose_folder(self):
        path = filedialog.askdirectory(title="Select a folder to scan")
        if path:
            self.path = path
            self.file_label.config(text=path, fg=TEXT)
            self.draw_gauge(0, 0, GREEN)
            self.file_count_label.config(text="Ready to scan folder")
            self.write_report("Selected folder:\\n" + path + "\\n\\nClick “Scan selected file” to scan its files.")

    def inspect_bytes(self, data, item_name):
        found = []
        low = data.lower()
        for signature, label, severity in PATTERNS:
            if signature in low:
                found.append((item_name, label, severity))
        return found

    def scan(self):
        if not self.path:
            messagebox.showinfo("VirusEz", "Insert a file or folder first.")
            return
        if not os.path.exists(self.path):
            messagebox.showerror("VirusEz", "The selected file or folder no longer exists.")
            return

        try:
            self.scan_button.config(state="disabled")
            self.root.update_idletasks()
            items = []
            findings = []

            if os.path.isdir(self.path):
                root_folder = os.path.abspath(self.path)
                for current_dir, _, filenames in os.walk(root_folder):
                    for filename in filenames:
                        full_path = os.path.join(current_dir, filename)
                        relative_name = os.path.relpath(full_path, root_folder)
                        try:
                            file_items, file_findings = self.inspect_path(full_path, relative_name)
                            items.extend(file_items)
                            findings.extend(file_findings)
                        except (OSError, PermissionError, zipfile.BadZipFile, tarfile.TarError):
                            items.append(relative_name + " (could not inspect)")
            else:
                items, findings = self.inspect_path(self.path, os.path.basename(self.path))

            self.file_items = items
            self.findings = findings
            total = len(items)
            flagged_names = sorted({f[0] for f in findings})
            flagged = len(flagged_names)
            color = RED if any(f[2] == "High" for f in findings) else (YELLOW if findings else GREEN)
            self.draw_gauge(flagged, total, color)
            self.file_count_label.config(text=f"{total} item(s) inspected")
            self.write_report_from_scan(items, findings, flagged, total)
        except (OSError, PermissionError, zipfile.BadZipFile, tarfile.TarError) as exc:
            messagebox.showerror("VirusEz scan error", str(exc))
        finally:
            self.scan_button.config(state="normal")

    def inspect_path(self, path, display_name):
        items = []
        findings = []

        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                members = [m for m in archive.infolist() if not m.is_dir()]
                for member in members:
                    try:
                        data = archive.read(member)[:8 * 1024 * 1024]
                        item_name = display_name + " / " + member.filename
                        items.append(item_name)
                        findings.extend(self.inspect_bytes(data, item_name))
                    except (RuntimeError, OSError, zipfile.BadZipFile):
                        items.append(display_name + " / " + member.filename + " (could not inspect)")
        elif tarfile.is_tarfile(path):
            with tarfile.open(path, "r:*") as archive:
                members = [m for m in archive.getmembers() if m.isfile()]
                for member in members:
                    stream = archive.extractfile(member)
                    data = stream.read(8 * 1024 * 1024) if stream else b""
                    item_name = display_name + " / " + member.name
                    items.append(item_name)
                    findings.extend(self.inspect_bytes(data, item_name))
        else:
            with open(path, "rb") as f:
                data = f.read(16 * 1024 * 1024)
            strings = re.findall(rb"[\\x20-\\x7e]{6,}", data)
            items = [display_name]
            findings.extend(self.inspect_bytes(data, display_name))

        if not items:
            items = [display_name]
        return items, findings

    def write_report_from_scan(self, items, findings, flagged, total):
        self.report.config(state="normal")
        self.report.delete("1.0", "end")
        self.report.insert("end", f"ITEMS INSPECTED: {total}\n")
        self.report.insert("end", f"ITEMS WITH MATCHING INDICATORS: {flagged}\n\n")
        if findings:
            self.report.insert("end", "SUSPICIOUS ITEMS\n", "bad")
            unique = {}
            for item, name, severity in findings:
                unique.setdefault(item, []).append((name, severity))
            for item, matches in unique.items():
                self.report.insert("end", f"\n{item}\n", "warn")
                for name, severity in matches:
                    tag = "bad" if severity == "High" else ("warn" if severity == "Medium" else "muted")
                    self.report.insert("end", f"  • {name}  [{severity}]\n", tag)
        else:
            self.report.insert("end", "NO MATCHING SUSPICIOUS INDICATORS FOUND\n", "good")
        self.report.insert("end", "\n\nNote: These are heuristic matches, not a malware verdict. "
                           "A clean scan does not guarantee safety. Some file types are only inspected "
                           "as raw bytes; archives are counted by their contained files. Nested archives "
                           "and many complex formats are not unpacked.", "muted")
        self.report.config(state="disabled")

    def write_report(self, text):
        self.report.config(state="normal")
        self.report.delete("1.0", "end")
        self.report.insert("end", text)
        self.report.config(state="disabled")

    def delete_file(self):
        if not self.path or not os.path.isfile(self.path):
            messagebox.showinfo("VirusEz", "Select a file first.")
            return
        name = os.path.basename(self.path)
        confirm = messagebox.askyesno(
            "Delete selected file?",
            f"This permanently deletes:\n\n{name}\n\nThis action cannot be undone. Continue?"
        )
        if not confirm:
            return
        try:
            os.remove(self.path)
            self.path = None
            self.file_label.config(text="No file or folder selected", fg="#718096")
            self.draw_gauge(0, 0, GREEN)
            self.file_count_label.config(text="File deleted")
            self.write_report(f"Deleted file:\n{name}\n\nChoose another file to scan.")
        except OSError as exc:
            messagebox.showerror("VirusEz", f"Could not delete the file:\n{exc}")

if __name__ == "__main__":
    root = tk.Tk()
    app = VirusEz(root)
    root.mainloop()
