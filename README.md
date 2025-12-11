# BasicAV - Educational Antivirus in C

**Educational antivirus project written in pure C for Windows**

A learning project focused on systems programming, Windows API, database operations, and modular architecture in C. This is NOT production-ready security software - it's designed for understanding how antivirus software works under the hood.

---

## What it does

BasicAV scans files on your system, calculates their SHA-256 hashes, and compares them against a database of known malware signatures from MalwareBazaar. When threats are detected, it generates both CSV and HTML reports.

**Current features:**
- SHA-256 file hashing using Windows CryptoAPI
- Recursive directory scanning
- SQLite database for storing file hashes and malware signatures
- Integration with MalwareBazaar's malware database (100,000+ signatures)
- Threat detection via hash comparison
- Professional HTML and CSV reports

**Planned additions:**
- Real-time file monitoring
- Quarantine system for detected threats
- Configuration file support
- Context menu integration (right-click "Scan with BasicAV")

---

## Project structure
```
BasicAV/
├── Logger/          - Logging system (writes to file and console)
├── Hash/            - SHA-256 calculator using Windows CryptoAPI
├── Scanner/         - Recursive directory scanner
├── Database/        - SQLite wrapper for file hashes and malware signatures
├── Reporter/        - CSV and HTML report generator
├── MalwareDB/       - CSV importer for MalwareBazaar database
├── Downloader/      - PowerShell scripts to fetch malware signatures
└── main.c           - Main program logic
```

---

## Getting started

**Requirements:**
- Windows 10 or 11
- Visual Studio 2019 or newer (MSVC compiler)
- PowerShell 5.1 or newer

**Building the project:**

1. Clone this repository
```bash
git clone https://github.com/LazyScriptTurtle/BasiC_AV.git
cd BasiC_AV
```

2. Download malware signatures using PowerShell
```powershell
cd Downloader
.\malware_bazzar_connector.ps1 -downloadFreshhashes "Yes" <-- Download all hashehs from 24h. If it run first time then download all available hashes from MalwareBazzar
```

3. Compile using Developer Command Prompt for Visual Studio
```cmd
cl Logger\logger.c Database\database.c Database\sqlite3.c Hash\hash.c ^
   Scanner\scanner.c Reporter\reporter.c MalwareDB\malware_db.c main.c ^
   Advapi32.lib /Fe:BasicAV.exe
```

4. Run the executable
```cmd
BasicAV.exe
```

---

## How it works

**First run:**
1. Creates SQLite database with two tables (scanned files and malware signatures)
2. Imports malware signatures from CSV files
3. Scans critical directories (Downloads, Desktop, AppData\Local\Temp, Documents)
4. Stores SHA-256 hashes of all scanned files
5. Creates a marker file to track first run completion

**Subsequent runs:**
1. Loads the database
2. Compares scanned file hashes against known malware signatures
3. Generates threat reports (CSV and HTML formats)

**Report outputs:**

CSV format (threats.csv):
```csv
Filepath,SHA256,Malware Name,Type,First Seen,Reporter,Detection Date
C:\test.exe,abc123...,Trojan.Win32.Agent,exe,2024-01-15,MalwareBazaar,2025-12-11
```

HTML format: Dark-themed dashboard with metrics cards and detailed threat table

---

## What I learned building this

**C programming concepts:**
- Dynamic memory management (malloc, realloc, free)
- Structures and pointers
- Forward declarations for circular dependencies
- String handling and buffer overflow protection
- Variadic functions for logging

**Windows API:**
- CryptoAPI for SHA-256 hashing
- File system operations (FindFirstFile, FindNextFile)
- User information retrieval

**Database operations:**
- SQLite prepared statements (prevents SQL injection)
- Transaction batching for performance
- Efficient CSV parsing

**Software design:**
- Modular architecture
- Separation of concerns
- Error handling patterns
- Callback functions

---

## Known issues

- No real-time protection (scan-on-demand only)
- Scans system folders that should be skipped (Windows\System32, etc.)
- No recursion depth limit
- Detected threats are logged but not quarantined

---

## Configuration

You can modify scan paths in scanner.c:
```c
char *paths[] = {
    "C:\\Users\\%USERNAME%\\Downloads",
    "C:\\Users\\%USERNAME%\\Desktop",
    "C:\\Users\\%USERNAME%\\AppData\\Local\\Temp",
    "C:\\Windows\\Temp",
    "C:\\Users\\%USERNAME%\\Documents",
    NULL
};
```

Database location is set in main.c:
```c
init_database("BasicAV.sqlite3");
```

---

## Next steps

The next major feature planned is real-time file monitoring using Windows ReadDirectoryChangesW API. This will enable BasicAV to automatically scan new or modified files as they appear on the system.

Other improvements:
- Add system folder blacklist
- Implement recursion depth limits
- Create configuration file parser (INI format)
- Add quarantine functionality
- Implement context menu integration

---

## Resources used

- MalwareBazaar API: https://bazaar.abuse.ch/api/
- SQLite documentation: https://www.sqlite.org/docs.html
- Windows CryptoAPI: https://learn.microsoft.com/en-us/windows/win32/seccrypto/

---

## Contributing

This is an educational project. Feel free to fork it, report bugs, or suggest improvements. The goal is learning, not building production antivirus software.

---

## License

Educational use only. Not intended for production use as antivirus software.

---

Made as a learning project for systems programming and Windows API
