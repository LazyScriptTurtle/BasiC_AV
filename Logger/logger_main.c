#include "logger.h"

int main() {
    log_info("Program started");
    log_info("Found %d files", 42);
    log_warning("Skipped folder: %s", "C:\\Windows");
    log_error("SQL error: %s", "database locked");
    
    return 0;
}