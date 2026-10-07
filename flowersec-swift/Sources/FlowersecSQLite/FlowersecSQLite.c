#include "FlowersecSQLite.h"
#include <stddef.h>

int flowersec_sqlite_no_checkpoint_on_close(sqlite3 *database, int enabled) {
    if (database == NULL || (enabled != 0 && enabled != 1)) {
        return SQLITE_MISUSE;
    }
    int observed = -1;
    int result = sqlite3_db_config(database, SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
                                  enabled, &observed);
    if (result != SQLITE_OK) {
        return result;
    }
    return observed == enabled ? SQLITE_OK : SQLITE_ERROR;
}
