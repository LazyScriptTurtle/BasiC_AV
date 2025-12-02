#include "Logger\logger.h"
#include "Hash\hash.h"
#include "Scanner\scanner.h"
#include "Database\database.h"
#include <stdio.h>
#include "MalwareDB\malware_db.h"
int main() {
    if(!file_exists("BasicAV.sqlite3")){
        log_info("Creating Database");
    init_database("BasicAV.sqlite3");
    log_info("Loading malware database...");
int count = load_malware_csv("Downloader\\full.csv", "MalwareBazaar_Full");
if (count > 0) {
    char msg[128];
    sprintf(msg, "Loaded %d malware signatures", count);
    log_info(msg);
}
    }
    
    if (!file_exists("Database\\first_run.txt")) {
        log_info("First run detected - full system scan");
        scan_all_drives();
        
        FILE* flag = fopen("Database\\first_run.txt", "w");
        fprintf(flag, "Initial scan completed");
        fclose(flag);
    } else {
        log_info("Monitoring mode - watching critical directories");
    }
    
    return 0;
}