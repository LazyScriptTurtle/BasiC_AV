# 🛡️ BasicAV - Educational Antivirus in C

![Language](https://img.shields.io/badge/Language-C-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![Database](https://img.shields.io/badge/Database-SQLite3-green)
![License](https://img.shields.io/badge/License-Educational-orange)

**BasicAV** is an educational antivirus project written in pure C for Windows, designed to teach:
- Systems programming (Windows API, CryptoAPI)
- Memory management (malloc, realloc, free)
- SQLite database operations
- Modular architecture
- Malware signature matching

> ⚠️ **WARNING:** This is an educational project. Do NOT use as primary antivirus protection.

---

## ✨ Features

### ✅ **Currently Implemented**
- **SHA-256 Hashing** - Fast chunk-based file hashing using Windows CryptoAPI
- **Recursive Directory Scanner** - Scans drives/folders and stores hashes in SQLite
- **Malware Signature Database** - Integration with MalwareBazaar (100k+ signatures)
- **Threat Detection** - Compares scanned files against known malware hashes
- **CSV/HTML Reports** - Professional Windows Defender-style threat reports
- **Logging System** - Timestamped logs to file and console

### ⏳ **Planned Features**
- **Real-time File Monitor** - Auto-scan new/modified files (ReadDirectoryChangesW)
- **Quarantine Module** - Isolate detected threats
- **Config Parser** - INI-based configuration
- **Context Menu Integration** - Right-click "Scan with BasicAV"
- **Auto-Update Signatures** - Scheduled malware database updates

---

## 🏗️ Architecture
```
BasicAV/
├── Logger/          # Logging system (file + console)
├── Hash/            # SHA-256 calculator (CryptoAPI)
├── Scanner/         # Recursive directory scanner
├── Database/        # SQLite wrapper (scanned_files + malware_hashes)
├── Reporter/        # CSV/HTML report generator
├── MalwareDB/       # CSV importer for MalwareBazaar
├── Downloader/      # PowerShell scripts (API fetch)
└── main.c           # Main orchestrator
```

---

## 🚀 Quick Start

### **Prerequisites**
- Windows 10/11
- Visual Studio 2019+ (MSVC compiler)
- PowerShell 5.1+

### **Installation**

1. **Clone the repository**
```bash
git clone https://github.com/LazyScriptTurtle/BasiC_AV.git
cd BasiC_AV
```

2. **Download malware signatures** (PowerShell)
```powershell
cd Downloader
.\download_recent.ps1    # Last 24h (fast)
.\download_full.ps1      # Full database (slow, 100k+ signatures)
```

3. **Compile** (Developer Command Prompt)
```cmd
cl Logger\logger.c Database\database.c Database\sqlite3.c Hash\hash.c ^
   Scanner\scanner.c Reporter\reporter.c MalwareDB\malware_db.c main.c ^
   Advapi32.lib /Fe:BasicAV.exe
```

4. **Run**
```cmd
BasicAV.exe
```

---

## 📊 How It Works

### **1. First Run (Initialization)**
```
1. Create SQLite database (scanned_files + malware_hashes)
2. Import malware signatures from CSV
3. Scan critical directories:
   - Downloads
   - Desktop
   - AppData\Local\Temp
   - Documents
4. Store SHA-256 hashes in database
5. Mark first_run.txt
```

### **2. Subsequent Runs (Threat Scan)**
```
1. Load database
2. SQL JOIN: scanned_files ⋈ malware_hashes (on SHA-256)
3. Generate reports:
   - threats.csv (machine-readable)
   - threats.html (human-readable dashboard)
```

### **3. Report Example**

**CSV Output:**
```csv
Filepath,SHA256,Malware Name,Type,First Seen,Reporter,Detection Date
C:\test.exe,abc123...,Trojan.Win32.Agent,exe,2024-01-15,MalwareBazaar,2025-12-11
```

**HTML Dashboard:**
- Dark mode design (Windows Defender style)
- 3 metric cards: Files Scanned | Threats Found | Status
- Detailed threat table with all metadata
- Responsive layout

---

## 🧠 What I Learned

### **C Programming**
- `malloc()`, `realloc()`, `free()` - dynamic memory management
- Structures (`typedef struct`) and pointers (`->`)
- Forward declarations (solving circular dependencies)
- String handling (`strncpy`, buffer overflow protection)
- Variadic functions (`va_list`, `va_start`)

### **Windows API**
- **CryptoAPI** - `CryptAcquireContext`, `CryptCreateHash`, `CryptHashData`
- **File System** - `FindFirstFile`, `FindNextFile`, `GetFileAttributes`
- **User Info** - `GetUserName`

### **Database**
- SQLite prepared statements (SQL injection prevention)
- Transaction batching (10k inserts at once)
- Efficient CSV parsing (65k line buffer)

### **Software Engineering**
- Modular architecture (separation of concerns)
- Error handling patterns
- Callback pattern (function pointers)
- Memory leak prevention

---

## 🐛 Known Issues

1. **UTF-8 Emoji Corruption** - HTML report uses corrupted emoji encoding
2. **No Real-time Protection** - Currently scan-on-demand only
3. **No Quarantine** - Detected threats are logged but not isolated
4. **System Folder Scanning** - Should skip `C:\Windows\System32` etc.

---

## 🔧 Configuration

Edit these constants in source files:

**Scanner (scanner.c)**
```c
char *paths[] = {
    "C:\\Users\\%USERNAME%\\Downloads",
    "C:\\Users\\%USERNAME%\\Desktop",
    // Add more paths...
};
```

**Database (database.c)**
```c
char DB_PATH[256] = "BasicAV.sqlite3";
```

---

## 📈 Roadmap

- [ ] **Real-time File Monitor** (ReadDirectoryChangesW)
- [ ] **Quarantine Module** (move to safe location)
- [ ] **Config Parser** (config.ini)
- [ ] **Context Menu Integration** (Registry)
- [ ] **Auto-Update Service** (Task Scheduler)
- [ ] **Web Dashboard** (local HTTP server)

---

## 📚 Resources

- **MalwareBazaar API**: https://bazaar.abuse.ch/api/
- **SQLite Documentation**: https://www.sqlite.org/docs.html
- **Windows CryptoAPI**: https://learn.microsoft.com/en-us/windows/win32/seccrypto/

---

## 🤝 Contributing

This is an educational project. Feel free to:
- Report bugs
- Suggest improvements
- Fork and experiment

---

## 📝 License

Educational use only. Not licensed for production antivirus use.

---

## 🙏 Acknowledgments

- **MalwareBazaar** for free malware signature database
- **SQLite** for embedded database engine
- **Microsoft** for comprehensive Windows API documentation

---

**Made with ❤️ for learning C and systems programming**