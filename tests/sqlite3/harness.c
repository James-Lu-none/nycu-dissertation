#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 0;
    
    char *sql = (char *)malloc(size + 1);
    if (!sql) {
        sqlite3_close(db);
        return 0;
    }
    memcpy(sql, data, size);
    sql[size] = '\0';
    
    // Execute SQL
    sqlite3_exec(db, sql, NULL, NULL, NULL);
    
    free(sql);
    sqlite3_close(db);
    return 0;
}
