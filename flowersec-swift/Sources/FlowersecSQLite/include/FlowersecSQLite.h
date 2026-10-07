#ifndef FLOWERSEC_SQLITE_H
#define FLOWERSEC_SQLITE_H

#include <sqlite3.h>

// Swift cannot call sqlite3_db_config's C variadic interface directly.
// This fixed operation also verifies the setting accepted by SQLite.
int flowersec_sqlite_no_checkpoint_on_close(sqlite3 *database, int enabled);

#endif
