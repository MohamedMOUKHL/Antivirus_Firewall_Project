# Basic Antivirus and Firewall Solution

## Author
**Mohamed MOUKHLISSI**  
GitHub: [MohamedMOUKHL]( https://github.com/MohamedMOUKHL)

## Description
This project implements a basic antivirus and firewall system using Python. The antivirus component scans files for malware using signature-based detection, while the firewall component blocks unauthorized network traffic. The project also includes a graphical user interface (GUI) for ease of use.

## Features
- **Antivirus**:
  - Scans files for malware using MD5 hash signatures.
  - Quarantines detected malware.
- **Firewall**:
  - Blocks traffic from specified IP addresses.
- **GUI**:
  - Provides a user-friendly interface for scanning files and blocking IPs.

## How to Use
1. Clone the repository:
   ```bash
   git clone https://github.com/MohamedMOUKHL/Antivirus_Firewall_Project.git

1- Navigate to the project folder:
cd Antivirus_Firewall_Project
2- Run the GUI:
python gui.py

Requirements:

Python 3.x
Libraries: os, hashlib, shutil, socket, tkinter
