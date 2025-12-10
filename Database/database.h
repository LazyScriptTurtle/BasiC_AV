#ifndef DATABASE_H
#define DATABASE_H
struct ThreatReport;


void init_database(char* db_path);
void insert_file_record(char* filepath, char* hash);
void insert_malware_hash(char *sha256, char *file_name, char *file_type, char *first_seen, char *reporter);
int compare_hashes(struct ThreatReport *report);

#endif