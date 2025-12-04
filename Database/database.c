#include "database.h"
#include "sqlite3.h"
#include "stdio.h"
#include "..\Logger\logger.h"
#include <string.h>
char DB_PATH[256] = "";

void init_database(char *db_path)
{
    strcpy(DB_PATH, db_path);
    sqlite3 *db;
    int rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK)
    {
        log_error("Cannot Open database");
        sqlite3_close(db);
        return;
    }

    char *sql = "CREATE TABLE IF NOT EXISTS scanned_files ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "filepath TEXT NOT NULL, "
                "sha256_hash TEXT NOT NULL, "
                "scan_date TEXT NOT NULL);";

    char *err_msg = 0;
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);

    if (rc != SQLITE_OK)
    {
        printf("SQL error: %s\n", err_msg);
        log_error("SQL error");
        sqlite3_free(err_msg);
        log_error("Failed to create table");
    }
    else
    {
        log_info("Database initialized successfully");
    }
    char *sql2 = "CREATE TABLE IF NOT EXISTS malware_hashes ("
                 "sha256	TEXT PRIMARY KEY, "
                 "file_name	TEXT, "
                 "file_type	TEXT, "
                 "first_seen	TEXT, "
                 "reporter	TEXT NOT NULL);";

    rc = sqlite3_exec(db, sql2, 0, 0, &err_msg);
    if (rc != SQLITE_OK)
    {
        printf("SQL error: %s\n", err_msg);
        log_error("Malware table SQL error");
        sqlite3_free(err_msg);
        log_error("Failed to create table");
    }
    else
    {
        log_info("Malware table created successfully");
    }
    sqlite3_close(db);
}

void insert_file_record(char *filepath, char *hash)
{

    sqlite3 *db;
    char sql[1024];
    int rc = sqlite3_open(DB_PATH, &db);
    if (rc != SQLITE_OK)
    {
        log_error("Cannot Open database");
        sqlite3_close(db);
        return;
    }
    sprintf(sql, "INSERT INTO scanned_files (filepath, sha256_hash, scan_date) VALUES ('%s', '%s', datetime('now'))", filepath, hash);
    char *err_msg = 0;
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);

    if (rc != SQLITE_OK)
    {
        printf("SQL error: %s\n", err_msg);
        log_error("SQL error");
        sqlite3_free(err_msg);
        log_error("Failed to insert recrod");
    }
    // else
    // {
    //     log_info("Record inserted successfully");
    // }
    sqlite3_close(db);
}

void insert_malware_hash(char *sha256, char *file_name, char *file_type, char *first_seen, char *reporter)
{
    sqlite3 *db;
    int rc = sqlite3_open(DB_PATH, &db);

    if (rc != SQLITE_OK)
    {
        log_error("Cannot Open database");
        sqlite3_close(db);
        return;
    }

    char *sql = "INSERT OR IGNORE INTO malware_hashes(sha256, file_name, file_type, first_seen, reporter) VALUES (?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        log_error("Failed to prepare statement");
        sqlite3_close(db);
        return;
    }

    sqlite3_bind_text(stmt, 1, sha256, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, file_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, file_type, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, first_seen, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, reporter, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE)
    {
        log_error("Failed to insert malware hash");
    } // else {
    //    log_info("Malware hash inserted successfully");
    //}

    sqlite3_finalize(stmt);

    sqlite3_close(db);
}

int compare_hashes(void)
{
    log_info("Starting searching malware...");

    sqlite3 *db;
    int rc = sqlite3_open(DB_PATH, &db);
    if (rc != SQLITE_OK)
    {
        log_error("Cannot open Database fo comparison");
        return -1;
    }
    const char *sql = "SELECT s.filepath, s.sha256_hash "
                      "FROM scanned_files s "
                      "INNER JOIN malware_hashes m ON s.sha256_hash = m.sha256";

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        log_error("Failed to prepare statement: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    int threat_count = 0;

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        const char *filepath = (const char *)sqlite3_column_text(stmt, 0);
        const char *hash = (const char *)sqlite3_column_text(stmt, 1);

        threat_count++;
        log_warning("THREAT DETECTED: %s [%s]", filepath, hash);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    log_info("Malware search complete. Threats found: %d", threat_count);
    return threat_count;

}