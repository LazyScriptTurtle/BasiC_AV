#include "Logger\logger.h"
#include "Hash\hash.h"
#include "Scanner\scanner.h"
#include "Database\database.h"
#include <stdio.h>
#include "MalwareDB\malware_db.h"
int main()
{
    if (!file_exists("BasicAV.sqlite3"))
    {
        log_info("Creating Database");
        init_database("BasicAV.sqlite3");
        log_info("Loading malware database...");
        int count = load_malware_csv("Downloader\\full.csv", "MalwareBazaar_Full");
        if (count > 0)
        {
            char msg[128];
            sprintf(msg, "Loaded %d malware signatures", count);
            log_info(msg);
        }
    }

    if (!file_exists("Database\\first_run.txt"))
    {
        // log_info("First run detected - TESTING on limited folder");
        // scan_directory("C:\\Program Files (x86)\\Microsoft Visual Studio\2022\\BuildTools\\VC\\Auxiliary\\Build");

        log_info("First run detected - full system scan");
        scan_all_drives();

        log_info("Comparing files with malware database...");
        int threats = compare_hashes();

        if (threats > 0)
        {
            log_error("WARNING: %d threats detected on your system!", threats);
        }
        else if (threats == 0)
        {
            log_info("Good news: No threats detected.");
        }
        else
        {
            log_error("Error during comparison.");
        }

        FILE *flag = fopen("Database\\first_run.txt", "w");
        fprintf(flag, "Initial scan completed");
        fclose(flag);
    }
    else
    {
        log_info("Comparing files with malware database...");
        int threats = compare_hashes();

        if (threats > 0)
        {
            log_error("WARNING: %d threats detected on your system!", threats);
        }
        else if (threats == 0)
        {
            log_info("Good news: No threats detected.");
        }
        else
        {
            log_error("Error during comparison.");
        }
        log_info("Monitoring mode - watching critical directories");
    }

    return 0;
}