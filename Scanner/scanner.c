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
int directory_exists(char *path)
{
    DWORD attrib = GetFileAttributesA(path);
    
    return (attrib != INVALID_FILE_ATTRIBUTES && 
            (attrib & FILE_ATTRIBUTE_DIRECTORY));
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
        char msg[1045];
        sprintf(msg, "Cannot Open directory: %s", szDirWithPattern);
        log_warning(msg);
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
        char hash[65];
        if (calculate_file_hash(fullPath, hash) == 0)
        {
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

void fast_scan_critical_directory()
{

    char *paths[] = {
        "C:\\Users\\%USERNAME%\\Downloads",
        "C:\\Users\\%USERNAME%\\Desktop",
        "C:\\Users\\%USERNAME%\\AppData\\Local\\Temp",
        "C:\\Windows\\Temp",
        "C:\\Users\\%USERNAME%\\Documents",
        NULL};

    char username[256];
    DWORD size = sizeof(username);
    GetUserNameA(username, &size);

    for (int i = 0; paths[i] != NULL; i++)
    {
        char *pos = strstr(paths[i], "%USERNAME%");
        char expanded[MAX_PATH];
        if (pos != NULL)
        {
            int prefix_len = pos - paths[i];

            strncpy(expanded, paths[i], prefix_len);
            expanded[prefix_len] = '\0';
            strcat(expanded, username);
            strcat(expanded, pos + strlen("%USERNAME%"));
        }
        else
        {
            strcpy(expanded, paths[i]);
        }
        if (directory_exists(expanded))
        {
            log_info("Scanning: %s", expanded);
            scan_directory(expanded);
        }else{
            log_warning("PAth not found: %s", expanded);
        }
    }
}