#include <windows.h>
#include <string.h>
#include <stdio.h>
#include "..\Hash\hash.h"
#include "..\Database\database.h"
#include "..\Logger\logger.h"
#include "scanner.h"

int file_exists(char *filepath)
{
    FILE *file = fopen(filepath, "r");
    if (file == NULL)
    {
        return 0;
    }
    else
    {
        fclose(file);
        return 1;
    }
}

void scan_directory(char *path)
{

    WIN32_FIND_DATAA ffd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char szDirWithPattern[MAX_PATH];

    snprintf(szDirWithPattern, MAX_PATH, "%s\\*", path);
    hFind = FindFirstFileA(szDirWithPattern, &ffd);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        printf("%s\n", szDirWithPattern);
        log_warning("Cannot Open directory");
        return;
    }
    do
    {
        if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0)
        {
            continue;
        }
        char fullPath[MAX_PATH];
        snprintf(fullPath, MAX_PATH, "%s\\%s", path, ffd.cFileName);
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            scan_directory(fullPath);
        }
        else
        {
            char hash[65];
            calculate_file_hash(fullPath, hash);
            insert_file_record(fullPath, hash);
        }
    } while (FindNextFileA(hFind, &ffd) != 0);
    FindClose(hFind);
}

void scan_all_drives()
{
    DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; i++)
    {
        if (drives & (1 << i))
        {
            char log_msg[50];
            char drive_letter = 'A' + i;
            char drive_path[4];
            sprintf(log_msg, "Scanning drive: %c:\\", drive_letter);
            log_info(log_msg);
            sprintf(drive_path, "%c:\\", drive_letter);
            scan_directory(drive_path);
        }
    }
}