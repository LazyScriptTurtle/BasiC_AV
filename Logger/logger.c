#include "logger.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

void log_info(const char *format, ...)
{
    char timestamp[128];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    printf("[INFO] ");
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");

    FILE *file = fopen("Logs.txt", "a");
    if (file == NULL)
    {
        return;
    }

    fprintf(file, "%s [INFO] ", timestamp);

    va_start(args, format);
    vfprintf(file, format, args);
    va_end(args);

    fprintf(file, "\n");

    fflush(file);
    fclose(file);
}
void log_warning(const char *format, ...)
{
    char timestamp[128];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    printf("[WARNING] ");
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");

    FILE *file = fopen("Logs.txt", "a");
    if (file == NULL)
    {
        return;
    }

    fprintf(file, "%s [WARNING] ", timestamp);
    va_start(args, format);
    vfprintf(file, format, args);
    va_end(args);
    fprintf(file, "\n");

    fflush(file);
    fclose(file);
}

void log_error(const char *format, ...)
{
    char timestamp[128];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    printf("[ERROR] ");
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");

    FILE *file = fopen("Logs.txt", "a");
    if (file == NULL)
    {
        return;
    }

    fprintf(file, "%s [ERROR] ", timestamp);
    va_start(args, format);
    vfprintf(file, format, args);
    va_end(args);
    fprintf(file, "\n");

    fflush(file);
    fclose(file);
}
