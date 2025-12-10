#ifndef REPORTER_H
#define REPORTER_H

#define MAX_PATH 260

typedef struct
{
    char filepath[MAX_PATH];
    char sha256_hash[65];
    char malware_name[256];
    char malware_type[64];
    char first_seen[32];
    char reporter[128];
    char detection_date[32];
} ThreatInfo;

typedef struct
{
    ThreatInfo *threats;
    int count;
    int capacity;
} ThreatReport;

void init_report(ThreatReport *report);
void add_threat(ThreatReport *report, ThreatInfo *threat);
void cleanup_report(ThreatReport *report);
void generate_csv_report(ThreatReport *report, const char *filename);
void generate_html_report(ThreatReport *report, const char *filename);

#endif