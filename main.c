#include "Logger\logger.h"
#include "Hash\hash.h"
#include "Scanner\scanner.h"
#include "Database\database.h"
#include <stdio.h>
#include "MalwareDB\malware_db.h"
#include "Reporter\reporter.h"

void initialize_system()
{
    log_info("System initialization");
    
    // POPRAWKA #1: Zawsze inicjalizuj bazę (ustawi DB_PATH)
    init_database("BasicAV.sqlite3");
    
    log_info("Loading malware database");
    int count = load_malware_csv("Downloader\\full.csv", "MalwareBazaar");
    if (count > 0)
    {
        char msg[128];
        sprintf(msg, "Loaded %d malware signatures", count);
        log_info(msg);
    }
    else
    {
        log_info("Loading RECENT malware signatures (24h)");
        int count = load_malware_csv("Downloader\\recent.csv", "MalwareBazaar");
        if (count > 0)
        {
            char msg[128];
            sprintf(msg, "Loaded %d new signatures", count);
            log_info(msg);
        }
    }
}

int is_first_run()
{
    // POPRAWKA #2: Zmień "rusn" na "run"
    return !file_exists("Database\\first_run.txt");
}

void mark_first_run_complete()
{
    log_info("Marking first run as complete");
    FILE *flag = fopen("Database\\first_run.txt", "w");
    if (flag)
    {
        fprintf(flag, "Initial scan completed");
        fclose(flag);
    }
}

void perform_initial_scan()
{
    log_info("First run detected - scanning all drives");
    //scan_all_drives();
    fast_scan_critical_directory();
}

void run_threat_scan()
{
    log_info("Searching for malicious files");
    
    ThreatReport report;
    init_report(&report);
    
    int threats = compare_hashes(&report);  
    
    if (threats == 0)
    {
        log_info("No threats found");
    }
    else if (threats > 0)
    {
        log_warning("Threats found: %d", threats);
        
        // Generuj raport
        generate_csv_report(&report, "threats.csv");
        log_info("CSV report saved: threats.csv");
        generate_html_report(&report, "threats.html");
    }
    else
    {
        log_error("Error during threat comparison");
    }
    
    cleanup_report(&report);
}

int main()
{
    initialize_system();
    
    if (is_first_run())
    {
        perform_initial_scan();
        mark_first_run_complete();
    }
    
    run_threat_scan();
    
    log_info("BasicAV finished");
    return 0;
}