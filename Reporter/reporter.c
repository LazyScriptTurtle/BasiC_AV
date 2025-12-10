#include "reporter.h"
#include "..\Logger\logger.h"
#include "..\Database\database.h"
#include "..\Database\sqlite3.h"
#include "stdio.h"
#include "stdlib.h"
#include <time.h>

extern char DB_PATH[256];

void init_report(ThreatReport *report)
{

    report->threats = malloc(sizeof(ThreatInfo) * 10);
    if (report->threats == NULL)
    {
        log_error("Failed to allocate memory for threat report");
        report->count = 0;
        report->capacity = 0;
        return;
    }
    report->count = 0;
    report->capacity = 10;
    log_info("Threat report initialized (capacity: %d)", report->capacity);
}

void add_threat(ThreatReport *report, ThreatInfo *threat)
{
    if (report->count >= report->capacity)
    {
        report->capacity = report->capacity * 2;
        ThreatInfo *new_threats = realloc(report->threats, sizeof(ThreatInfo) * report->capacity);

        if (new_threats == NULL)
        {
            log_error("Failed to reallocate memory for threats");
            return;
        }
        report->threats = new_threats;
        log_info("Threat report expanded to capacity: %d", report->capacity);
    }
    strncpy(report->threats[report->count].filepath, threat->filepath, MAX_PATH - 1);
    strncpy(report->threats[report->count].sha256_hash, threat->sha256_hash, 64);
    strncpy(report->threats[report->count].malware_name, threat->malware_name, 255);
    strncpy(report->threats[report->count].malware_type, threat->malware_type, 63);
    strncpy(report->threats[report->count].first_seen, threat->first_seen, 31);
    strncpy(report->threats[report->count].reporter, threat->reporter, 127);
    strncpy(report->threats[report->count].detection_date, threat->detection_date, 31);

    report->threats[report->count].filepath[MAX_PATH - 1] = '\0';
    report->threats[report->count].sha256_hash[64] = '\0';
    report->threats[report->count].malware_name[255] = '\0';
    report->threats[report->count].malware_type[63] = '\0';
    report->threats[report->count].first_seen[31] = '\0';
    report->threats[report->count].reporter[127] = '\0';
    report->threats[report->count].detection_date[31] = '\0';
    report->count++;
    log_info("Threat added. Total threats: %d", report->count);
}

void cleanup_report(ThreatReport *report)
{
    if (report->threats != NULL)
    {
        free(report->threats);
        report->threats = NULL;
    }
    report->count = 0;
    report->capacity = 0;
    log_info("Threat report cleaned up");
}

void generate_csv_report(ThreatReport *report, const char *filename)
{
    FILE *f = fopen(filename, "w");

    if (f == NULL)
    {
        log_error("Cannot create CS report %s", filename);
        return;
    }
    fprintf(f, "Filepath,SHA256,Malware Name,Type,First Seen,Reporter,Detection Date\n");

    for (int i = 0; i < report->count; i++)
    {
        ThreatInfo *threat = &report->threats[i];
        fprintf(f, "%s,%s,%s,%s,%s,%s,%s\n",
                threat->filepath,
                threat->sha256_hash,
                threat->malware_name,
                threat->malware_type,
                threat->first_seen,
                threat->reporter,
                threat->detection_date);
    }
    fclose(f);
}

void generate_html_report(ThreatReport *report, const char *filename)
{
    FILE *f = fopen(filename, "w");

    if (f == NULL)
    {
        log_error("Cannot create HTML report: %s", filename);
        return;
    }

    // Get current timestamp
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    // ===== HTML START + CSS =====
    fprintf(f, "<!DOCTYPE html>\n");
    fprintf(f, "<html lang=\"en\">\n");
    fprintf(f, "<head>\n");
    fprintf(f, "    <meta charset=\"UTF-8\">\n");
    fprintf(f, "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    fprintf(f, "    <title>BasicAV Security Report</title>\n");
    fprintf(f, "    <style>\n");

    // CSS
    fprintf(f, "        * { margin: 0; padding: 0; box-sizing: border-box; }\n");
    fprintf(f, "        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1e1e1e; color: #e0e0e0; padding: 20px; }\n");
    fprintf(f, "        .header { background: linear-gradient(135deg, #0078d4 0%%, #005a9e 100%%); padding: 30px; border-radius: 8px; margin-bottom: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }\n");
    fprintf(f, "        .header h1 { color: white; font-size: 28px; margin-bottom: 10px; }\n");
    fprintf(f, "        .header .subtitle { color: #c7e0f4; font-size: 14px; }\n");
    fprintf(f, "        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 30px; }\n");
    fprintf(f, "        .card { background: #2d2d2d; padding: 25px; border-radius: 8px; border-left: 4px solid #0078d4; box-shadow: 0 2px 4px rgba(0,0,0,0.3); transition: transform 0.2s; }\n");
    fprintf(f, "        .card:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.4); }\n");
    fprintf(f, "        .card-title { color: #888; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; }\n");
    fprintf(f, "        .card-value { color: white; font-size: 32px; font-weight: bold; margin-bottom: 5px; }\n");
    fprintf(f, "        .card-label { color: #aaa; font-size: 14px; }\n");
    fprintf(f, "        .card.threat { border-left-color: #d32f2f; }\n");
    fprintf(f, "        .card.threat .card-value { color: #ff5252; }\n");
    fprintf(f, "        .card.warning { border-left-color: #f57c00; }\n");
    fprintf(f, "        .card.warning .card-value { color: #ffa726; }\n");
    fprintf(f, "        .section-header { background: #2d2d2d; padding: 15px 20px; border-radius: 8px 8px 0 0; border-left: 4px solid #0078d4; margin-bottom: 0; }\n");
    fprintf(f, "        .section-header h2 { color: white; font-size: 18px; }\n");
    fprintf(f, "        .table-container { background: #252525; border-radius: 0 0 8px 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.3); }\n");
    fprintf(f, "        table { width: 100%%; border-collapse: collapse; }\n");
    fprintf(f, "        th { background: #1a1a1a; color: #0078d4; padding: 15px; text-align: left; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid #0078d4; }\n");
    fprintf(f, "        td { padding: 15px; border-bottom: 1px solid #333; color: #ccc; }\n");
    fprintf(f, "        tr:hover { background: #2d2d2d; }\n");
    fprintf(f, "        tr.threat-row { background: #2d1f1f; border-left: 3px solid #d32f2f; }\n");
    fprintf(f, "        tr.threat-row:hover { background: #3d2424; }\n");
    fprintf(f, "        .hash { font-family: 'Courier New', monospace; font-size: 11px; color: #888; word-break: break-all; }\n");
    fprintf(f, "        .malware-name { color: #ff5252; font-weight: bold; }\n");
    fprintf(f, "        .badge { display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 11px; font-weight: bold; }\n");
    fprintf(f, "        .badge-high { background: #d32f2f; color: white; }\n");
    fprintf(f, "        .badge-medium { background: #f57c00; color: white; }\n");
    fprintf(f, "        .footer { margin-top: 30px; text-align: center; color: #666; font-size: 12px; }\n");
    fprintf(f, "    </style>\n");
    fprintf(f, "</head>\n");
    fprintf(f, "<body>\n");

    // ===== HEADER =====
    fprintf(f, "    <div class=\"header\">\n");
    fprintf(f, "        <h1>🛡️ BasicAV Security Report</h1>\n");
    const char *status_msg = (report->count == 0) ? "System Protected" : "Action Required";
    fprintf(f, "        <div class=\"subtitle\">Scan completed on %s | %s</div>\n", timestamp, status_msg);
    fprintf(f, "    </div>\n");

    // ===== DASHBOARD =====
    fprintf(f, "    <div class=\"dashboard\">\n");

    // Pobierz scanned count
    sqlite3 *db;
    int scanned_count = 0;
    if (sqlite3_open(DB_PATH, &db) == SQLITE_OK)
    {
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM scanned_files", -1, &stmt, NULL) == SQLITE_OK)
        {
            if (sqlite3_step(stmt) == SQLITE_ROW)
            {
                scanned_count = sqlite3_column_int(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }

    // Card 1: Files Scanned
    fprintf(f, "        <div class=\"card\">\n");
    fprintf(f, "            <div class=\"card-title\">Files Scanned</div>\n");
    fprintf(f, "            <div class=\"card-value\">%d</div>\n", scanned_count);
    fprintf(f, "            <div class=\"card-label\">Total files analyzed</div>\n");
    fprintf(f, "        </div>\n");

    // Card 2: Threats
    fprintf(f, "        <div class=\"card threat\">\n");
    fprintf(f, "            <div class=\"card-title\">Threats Found</div>\n");
    fprintf(f, "            <div class=\"card-value\">%d</div>\n", report->count);
    fprintf(f, "            <div class=\"card-label\">Malicious files detected</div>\n");
    fprintf(f, "        </div>\n");

    // Card 3: Status
    fprintf(f, "        <div class=\"card warning\">\n");
    fprintf(f, "            <div class=\"card-title\">Status</div>\n");
    if (report->count == 0)
    {
        fprintf(f, "            <div class=\"card-value\">✅</div>\n");
        fprintf(f, "            <div class=\"card-label\">No Threats</div>\n");
    }
    else
    {
        fprintf(f, "            <div class=\"card-value\">⚠️</div>\n");
        fprintf(f, "            <div class=\"card-label\">Action Required</div>\n");
    }
    fprintf(f, "        </div>\n");

    // Card 4 USUNIĘTE!

    fprintf(f, "    </div>\n");

    // ===== TABLE =====
    fprintf(f, "    <div class=\"section-header\">\n");
    fprintf(f, "        <h2>🔍 Threat Details - Full Report</h2>\n");
    fprintf(f, "    </div>\n");

    fprintf(f, "    <div class=\"table-container\">\n");
    fprintf(f, "        <table>\n");
    fprintf(f, "            <thead>\n");
    fprintf(f, "                <tr>\n");
    fprintf(f, "                    <th>Filepath</th>\n");
    fprintf(f, "                    <th>SHA256</th>\n");
    fprintf(f, "                    <th>Malware Name</th>\n");
    fprintf(f, "                    <th>Type</th>\n");
    fprintf(f, "                    <th>First Seen</th>\n");
    fprintf(f, "                    <th>Reporter</th>\n");
    fprintf(f, "                    <th>Detection Date</th>\n");
    fprintf(f, "                </tr>\n");
    fprintf(f, "            </thead>\n");
    fprintf(f, "            <tbody>\n");

    for (int i = 0; i < report->count; i++)
    {
        ThreatInfo *threat = &report->threats[i];
        fprintf(f, "                <tr class=\"threat-row\">\n");
        fprintf(f, "                    <td>%s</td>\n", threat->filepath);
        fprintf(f, "                    <td class=\"hash\">%s</td>\n", threat->sha256_hash);
        fprintf(f, "                    <td><span class=\"malware-name\">%s</span> <span class=\"badge badge-high\">HIGH</span></td>\n", threat->malware_name);
        fprintf(f, "                    <td>%s</td>\n", threat->malware_type);
        fprintf(f, "                    <td>%s</td>\n", threat->first_seen);
        fprintf(f, "                    <td>%s</td>\n", threat->reporter);
        fprintf(f, "                    <td>%s</td>\n", threat->detection_date);
        fprintf(f, "                </tr>\n");
    }

    fprintf(f, "            </tbody>\n");
    fprintf(f, "        </table>\n");
    fprintf(f, "    </div>\n");

    // ===== FOOTER =====
    fprintf(f, "    <div class=\"footer\">\n");
    fprintf(f, "        <p>BasicAV Security Suite | Powered by MalwareBazaar Database</p>\n");
    fprintf(f, "        <p>Report generated automatically - Do not modify</p>\n");
    fprintf(f, "    </div>\n");

    fprintf(f, "</body>\n");
    fprintf(f, "</html>\n");

    fclose(f);
    log_info("HTML report saved: %s (%d threats)", filename, report->count);
}