"""
Author: Mohamed MOUKHLISSI
GitHub: https://github.com/MohamedMOUKHL
Project: Basic Antivirus and Firewall Solution
Description: This script provides a graphical user interface (GUI) for the antivirus and firewall system.
"""


import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
import os
import hashlib
import shutil
import socket
import threading

# Antivirus functions (from antivirus.py)
def load_signatures():
    with open("signatures.txt", "r") as f:
        return f.read().splitlines()

def calculate_hash(file_path):
    hasher = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def scan_files(directory):
    malware_found = []
    signatures = load_signatures()
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_hash(file_path)
            if file_hash in signatures:
                malware_found.append(file_path)
    return malware_found

def quarantine_files(files):
    quarantine_dir = "quarantine"
    os.makedirs(quarantine_dir, exist_ok=True)
    for file in files:
        shutil.move(file, quarantine_dir)
    return files

# Firewall functions
def load_blocklist():
    if not os.path.exists("blocklist.txt"):
        return []
    with open("blocklist.txt", "r") as f:
        return f.read().splitlines()

def monitor_traffic(logs_text):
    blocklist = load_blocklist()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 12345)
    sock.bind(server_address)
    sock.listen(5)
    logs_text.insert(tk.END, "Firewall started. Listening for connections...\n")

    while True:
        connection, client_address = sock.accept()
        src_ip = client_address[0]
        if src_ip in blocklist:
            logs_text.insert(tk.END, f"Blocked connection from {src_ip}\n")
            connection.close()
        else:
            logs_text.insert(tk.END, f"Allowed connection from {src_ip}\n")
            connection.sendall(b"Connection allowed.")
            connection.close()

# GUI Application
class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Antivirus and Firewall GUI")
        self.root.geometry("600x500")
        self.root.configure(bg="#f0f0f0")

        # Set a modern theme
        self.style = ttk.Style()
        self.style.theme_use("clam")

        # Main Frame
        self.main_frame = ttk.Frame(root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Antivirus Section
        self.antivirus_label = ttk.Label(self.main_frame, text="Antivirus Scanner", font=("Arial", 16, "bold"))
        self.antivirus_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))

        self.scan_button = ttk.Button(self.main_frame, text="Scan Directory", command=self.scan_directory, style="Accent.TButton")
        self.scan_button.grid(row=1, column=0, pady=10, padx=5, sticky=tk.W)

        self.result_label = ttk.Label(self.main_frame, text="", font=("Arial", 12))
        self.result_label.grid(row=2, column=0, columnspan=2, pady=10)

        # Logs Section
        self.logs_label = ttk.Label(self.main_frame, text="Logs", font=("Arial", 16, "bold"))
        self.logs_label.grid(row=3, column=0, columnspan=2, pady=(20, 10))

        self.logs_text = ScrolledText(self.main_frame, width=70, height=10, font=("Arial", 10))
        self.logs_text.grid(row=4, column=0, columnspan=2, pady=10, padx=5)

        # Firewall Section
        self.firewall_label = ttk.Label(self.main_frame, text="Firewall Monitor", font=("Arial", 16, "bold"))
        self.firewall_label.grid(row=5, column=0, columnspan=2, pady=(20, 10))

        self.block_ip_button = ttk.Button(self.main_frame, text="Block IP", command=self.block_ip, style="Accent.TButton")
        self.block_ip_button.grid(row=6, column=0, pady=10, padx=5, sticky=tk.W)

        # Start firewall monitoring in a separate thread
        self.firewall_thread = threading.Thread(target=monitor_traffic, args=(self.logs_text,), daemon=True)
        self.firewall_thread.start()

        # Configure styles
        self.style.configure("Accent.TButton", font=("Arial", 12), background="#4CAF50", foreground="white")
        self.style.map("Accent.TButton", background=[("active", "#45a049")])

    def scan_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.logs_text.insert(tk.END, f"Scanning directory: {directory}\n")
            infected_files = scan_files(directory)
            if infected_files:
                quarantined_files = quarantine_files(infected_files)
                self.result_label.config(text=f"Malware detected and quarantined: {quarantined_files}", foreground="red")
                self.logs_text.insert(tk.END, f"Malware detected: {quarantined_files}\n")
            else:
                self.result_label.config(text="No malware detected.", foreground="green")
                self.logs_text.insert(tk.END, "No malware detected.\n")

    def block_ip(self):
        ip = tk.simpledialog.askstring("Block IP", "Enter IP address to block:")
        if ip:
            with open("blocklist.txt", "a") as f:
                f.write(ip + "\n")
            messagebox.showinfo("Block IP", f"IP {ip} added to blocklist.")
            self.logs_text.insert(tk.END, f"Blocked IP: {ip}\n")

# Run the GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusApp(root)
    root.mainloop()