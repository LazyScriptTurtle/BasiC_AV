#ifndef SCANNER_H
#define SCANNER_H

int file_exists(char* filepath);
void scan_directory(char* path);
void scan_all_drives();
int directory_exists(char *path);
void fast_scan_critical_directory();
#endif