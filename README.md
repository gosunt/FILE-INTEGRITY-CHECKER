# FILE-INTEGRITY-CHECKER

*COMPANY*: CODTECH IT SOLUTIONS

*NAME*: Sunkara Gowtham

*INTERN ID*: CT08WM49

*DOMAIN*: Cyber Security & Ethical Hacking

*DURATION*: 8 WEEKS

*MENTOR*: Neela Santhosh

# The File Integrity Checker is a Python tool that helps keep your files safe by monitoring them for any unauthorized changes. It is especially useful for people who want to ensure that important files on their computer have not been tampered with, deleted, or replaced. This tool works by watching a specific folder on your system and checking the files inside it for any changes. If anything suspicious happens, it will log the event, alert the user, and take action like backing up the file or moving it to a secure location.

# One of the key features of this tool is that it checks whether it is being run with admin privileges. On Windows or Linux systems, some files cannot be accessed unless the script has administrative rights. That’s why the script first checks if it is running as an administrator, and if not, it either restarts itself with the required permissions (on Windows) or tells the user how to run it correctly using sudo on Linux. This is important to make sure it can monitor all files and perform secure operations like quarantining.

# The core part of this tool is based on file hashing. Hashing is like giving each file a unique fingerprint. When the script starts, it scans all files in the selected folder and creates a SHA-256 hash for each one. These hashes are stored in a file called hashes.json. Later, if any file changes, the script will recalculate the hash and compare it to the old one. If the hashes don’t match, that means the file has been changed.

# To make the monitoring continuous, the script uses a Python library called watchdog. This library watches the folder in real-time and detects events like file creation, modification, or deletion. Instead of checking manually or running the script again and again, it automatically reacts when something changes. This makes it suitable for use in systems where files need to be protected 24/7.

# When a file change is detected, the script doesn’t just log the change. It also checks the file using YARA rules. YARA is a tool used to detect malware or other threats by comparing files against known patterns of harmful behavior. If a file matches a YARA rule, the script marks it as dangerous. Even if there is no threat found, it also checks if the file has an acceptable extension (like .txt, .pdf, .py). If the file is of an unknown or unapproved type, it is also flagged.

# Flagged files are not deleted. Instead, they are first backed up and then moved to a quarantine folder. This folder is only accessible by the system administrator. That way, the files can’t harm the system or other users, but they’re still available if needed later. There’s also a built-in option to restore quarantined files from the backup if it turns out the change was legitimate.

# Another security feature is that the script checks itself. It stores its own hash and checks whether it has been changed. If someone tries to edit the script file itself, the tool will detect it, log a tampering alert, and stop running. This protects the integrity of the checker itself.

# All important events — such as changes, warnings, threats, or errors — are written to an alerts.log file. These logs include timestamps and the severity of the event (e.g., info, alert, error). This allows users and administrators to easily track what’s happening in the system.

## Finally, if the user tries to stop the script by pressing Ctrl+C, it catches that and asks if you want to continue monitoring or exit. If any unexpected errors happen, it will also restart the monitoring automatically after a short delay. This makes the tool reliable for long-term use without needing someone to keep restarting it manually.

#OUTPUT
![Image](https://github.com/user-attachments/assets/1d207dd2-92f9-4dc7-b83b-f0cbf83f3ab0)
