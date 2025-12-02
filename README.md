# BasicAV

> **Edukacyjny projekt antywirusowy w C dla Windows**  
> Nauka programowania systemowego przez budowanie prawdziwego narzędzia bezpieczeństwa

[![Language](https://img.shields.io/badge/Language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6.svg)](https://www.microsoft.com/windows)
[![Status](https://img.shields.io/badge/Status-In%20Development-yellow.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 📋 O Projekcie

BasicAV to podstawowy system antywirusowy dla Windows stworzony w czystym C. Projekt powstał jako **narzędzie edukacyjne** do nauki:
- Programowania w C od podstaw
- Windows API (Crypto, File System, Services)
- SQLite i baz danych
- Rekurencji i algorytmów
- Zarządzania pamięcią i wskaźników

⚠️ **To NIE jest produkcyjny antywirus!** Służy wyłącznie celom edukacyjnym.

## ✨ Funkcjonalności

### ✅ Zaimplementowane
- **Skaner plików** - rekurencyjne skanowanie dysków (C:\, D:\, E:\...)
- **Kalkulator hash** - SHA256 przez Windows Crypto API
- **Baza danych SQLite** - przechowywanie hashów plików i malware
- **Logger** - proste logowanie zdarzeń do konsoli
- **First Run Detection** - automatyczny pełny skan przy pierwszym uruchomieniu
- **Integracja z MalwareBazaar** - pobieranie aktualnej bazy malware (PowerShell)

### 🔄 W trakcie
- **Porównywanie hashów** - wykrywanie zagrożeń (JOIN SQL)

### 📅 Planowane
- Real-time monitoring folderów (Downloads, Temp)
- System raportowania (TXT/CSV)
- Windows Services (3 usługi)
- GUI / Terminal Panel
- Context Menu (prawy przycisk → "Scan with BasicAV")
- Parser plików konfiguracyjnych

## 🏗️ Architektura
```
BasicAV/
├── Logger/          # Moduł logowania
│   ├── logger.c
│   └── logger.h
├── Hash/            # Kalkulator SHA256
│   ├── hash.c
│   └── hash.h
├── Scanner/         # Skaner plików (rekurencyjny)
│   ├── scanner.c
│   └── scanner.h
├── Database/        # SQLite wrapper
│   ├── database.c
│   ├── database.h
│   ├── sqlite3.c
│   ├── sqlite3.h
│   └── BasicAV.sqlite3
├── main.c           # Core logic
└── BasicAV.exe      # Kompilowany program
```

**Baza danych** (BasicAV.sqlite3):
- `scanned_files` - lokalne pliki ze skanowania
- `malware_hashes` - znane zagrożenia z MalwareBazaar

## 🚀 Kompilacja

**Wymagania:**
- Windows 10/11
- MSVC (Visual Studio Build Tools)
- PowerShell 5.1+

**Kompilacja z Developer Command Prompt:**
```cmd
cl Logger\logger.c Database\database.c Database\sqlite3.c Hash\hash.c Scanner\scanner.c main.c Advapi32.lib /Fe:BasicAV.exe
```

## 💻 Użycie

**Pierwsze uruchomienie:**
```cmd
BasicAV.exe
```
Program automatycznie:
1. Utworzy bazę danych `BasicAV.sqlite3`
2. Przeskanuje wszystkie dostępne dyski
3. Pobierze bazę malware z MalwareBazaar
4. Utworzy flagę `first_run.txt`

**Kolejne uruchomienia:**
- Pomija pełny skan (czyta z bazy)
- TODO: Monitoring w czasie rzeczywistym

## 📊 Workflow

**First Run:**
```
START → Sprawdź first_run.txt → NIE ISTNIEJE
  ↓
Skanuj wszystkie dyski (C:\, D:\, E:\...)
  ↓
Dla każdego pliku: oblicz SHA256 + zapisz do DB
  ↓
Pobierz bazę malware z MalwareBazaar (PowerShell)
  ↓
Porównaj lokalne hashe z malware DB
  ↓
Wyświetl raport zagrożeń
```

**Normal Run:**
```
START → Sprawdź first_run.txt → ISTNIEJE
  ↓
Pomiń pełny skan
  ↓
TODO: Monitoring w czasie rzeczywistym
```

## 🛠️ Stack Technologiczny

- **Język:** C (Standard C99)
- **Kompilator:** MSVC
- **API:** Windows API (Advapi32, Kernel32)
- **Baza:** SQLite3
- **Crypto:** Windows Crypto API (CryptAcquireContext, SHA256)
- **Scripting:** PowerShell (update malware DB)

## 📚 Czego się nauczyłem

- ✅ Wskaźniki i zarządzanie pamięcią w C
- ✅ Windows File System API (FindFirstFile, FindNextFile)
- ✅ Rekurencja (skanowanie folderów)
- ✅ SQLite C API (prepare, step, finalize)
- ✅ Windows Crypto API (haszowanie SHA256)
- ✅ Bitmaski (GetLogicalDrives)
- ✅ Parametry wyjściowe przez wskaźniki
- 🔄 SQLite JOIN i zaawansowane zapytania

## 🎯 Cele projektu

1. **Nauka C** - priorytet #1
2. Zrozumienie Windows API
3. Praktyczna praca z bazami danych
4. Podstawy cyberbezpieczeństwa
5. Kod który działa > kod który jest "idealny"

## 📝 Status Modułów

| Moduł | Status | Nauka |
|-------|--------|-------|
| Logger | ✅ Complete | printf, funkcje |
| Hash Calculator | ✅ Complete | Windows Crypto API, wskaźniki |
| Scanner | ✅ Complete | Rekurencja, File API |
| Database | ✅ Complete | SQLite, INSERT |
| Compare Hashes | 🔄 In Progress | JOIN, SELECT |
| Real-time Monitor | ⏳ Planned | ReadDirectoryChangesW |
| Windows Services | ⏳ Planned | Service API |
| GUI | ⏳ Planned | Win32 API lub Terminal UI |

## 🔧 Struktura Kodu

### Logger Module
```c
void log_info(const char* message);
void log_warning(const char* message);
void log_error(const char* message);
```

### Hash Module
```c
int calculate_file_hash(const char* filepath, char* output_hash);
// Używa: CryptAcquireContext, CryptCreateHash, CryptHashData
```

### Scanner Module
```c
int file_exists(const char* filepath);
void scan_directory(const char* path);  // REKURENCJA!
void scan_all_drives();
// Używa: FindFirstFileA, FindNextFileA, GetLogicalDrives
```

### Database Module
```c
void init_database(const char* db_path);
void insert_file_record(const char* filepath, const char* hash);
void compare_hashes();  // TODO
// Używa: sqlite3_open, sqlite3_exec, sqlite3_prepare_v2
```

## 🗺️ Roadmap

### Phase 1: Core Functionality ✅
- [x] Logger
- [x] Hash Calculator
- [x] File Scanner
- [x] SQLite Database
- [x] First Run Logic
- [x] Malware DB Import

### Phase 2: Detection 🔄
- [x] Hash Comparison (compare_hashes)
- [ ] Threat Reporting

### Phase 3: Real-time Protection ⏳
- [ ] Directory Monitoring (ReadDirectoryChangesW)
- [ ] Windows Service #1: File Monitor
- [ ] Windows Service #2: CSV Import
- [ ] Scheduled Task: DB Update

### Phase 4: User Interface ⏳
- [ ] Configuration File Parser
- [ ] Terminal UI / Win32 GUI
- [ ] Context Menu Integration

## ⚖️ Licencja

MIT License - projekt edukacyjny, używaj na własną odpowiedzialność.

## ⚠️ Disclaimer

Ten projekt jest **wyłącznie edukacyjny**. Nie jest to profesjonalne oprogramowanie antywirusowe i nie powinno być używane jako jedyne zabezpieczenie systemu. Zawsze korzystaj z renomowanych rozwiązań bezpieczeństwa na produkcyjnych systemach.

**Ostrzeżenie:** Skanowanie całego dysku może zająć dużo czasu i zasobów systemowych.

## 🤝 Contributing

Projekt osobisty do nauki - pull requesty nie są przyjmowane, ale sugestie i feedback mile widziane w Issues!

## 📧 Kontakt

Pytania? Otwórz Issue na GitHubie!

---

**Projekt edukacyjny** | **2024** | **Windows Only**
