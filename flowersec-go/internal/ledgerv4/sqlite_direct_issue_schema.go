package ledgerv4

import "database/sql/driver"

const sqliteDirectIssueConfigSQL = `CREATE TABLE direct_issue_config (id INTEGER PRIMARY KEY CHECK(id=1), configuration BLOB NOT NULL CHECK(length(configuration) BETWEEN 1 AND 8192), rows INTEGER NOT NULL CHECK(rows>=0), state_bytes INTEGER NOT NULL CHECK(state_bytes>=0), credit BLOB NOT NULL CHECK(length(credit)=8), last_upper BLOB NOT NULL CHECK(length(last_upper)=8)) STRICT, WITHOUT ROWID`
const sqliteDirectIssueSQL = `CREATE TABLE issuance (lease BLOB PRIMARY KEY CHECK(length(lease) BETWEEN 34 AND 161), request BLOB NOT NULL CHECK(length(request)=32), invocation BLOB NOT NULL CHECK(length(invocation)=16), fence BLOB NOT NULL CHECK(length(fence)=8), state INTEGER NOT NULL CHECK(state IN (0,1,2)), version BLOB NOT NULL CHECK(length(version)=8), artifact BLOB NOT NULL CHECK(length(artifact)=32), projection BLOB NOT NULL CHECK(length(projection) BETWEEN 1 AND 4096), retirement BLOB NOT NULL DEFAULT x'' CHECK(length(retirement) IN (0,88)), CHECK((state=2 AND length(retirement)=88) OR (state<>2 AND length(retirement)=0))) STRICT, WITHOUT ROWID`
const sqliteDirectIssueRequestSQL = `CREATE UNIQUE INDEX issuance_request ON issuance(request)`

type sqliteSchemaObject struct{ kind, name, sql string }

// The physical cap covers all purpose rows, including callers whose early
// capacity observation predates a concurrent original issuance reservation.
// Fixed transaction counters and actual row insertion share one commit.
func sqliteMainSchemaObjects() []sqliteSchemaObject {
	objects := []sqliteSchemaObject{{"table", "manifest", sqliteManifestSQL}, {"table", "admission", sqliteAdmissionSQL}, {"table", "spend", sqliteSpendSQL}, {"table", "parent_winner", sqliteParentWinnerSQL}, {"table", "direct_issue_config", sqliteDirectIssueConfigSQL}, {"table", "issuance", sqliteDirectIssueSQL}, {"index", "issuance_request", sqliteDirectIssueRequestSQL}, {"table", "relay_issuance", sqliteRelayRegistrationSQL}, {"table", "relay_parent", sqliteRelayParentSQL}, {"table", "relay_leg", sqliteRelayLegSQL}, {"trigger", "relay_parent_aggregate_capacity", sqliteRelayCapacitySQL}}
	for _, table := range []string{"admission", "spend", "parent_winner", "issuance", "relay_issuance"} {
		name := table + "_aggregate_capacity"
		sql := `CREATE TRIGGER ` + name + ` BEFORE INSERT ON ` + table + ` WHEN (SELECT admission_rows+spend_rows+winner_rows+issuance_rows+relay_rows>=max_records FROM manifest WHERE id=1) BEGIN SELECT RAISE(ABORT,'aggregate capacity'); END`
		objects = append(objects, sqliteSchemaObject{"trigger", name, sql})
	}
	return objects
}

func sqliteMainSchemaSQL() []string {
	objects := sqliteMainSchemaObjects()
	sql := make([]string, len(objects))
	for i := range objects {
		sql[i] = objects[i].sql
	}
	return sql
}

func (s *sqliteStore) verifyDirectIssuanceRows(expected int64) error {
	n, err := s.scalar("SELECT count(*) FROM issuance")
	if err != nil {
		return err
	}
	if n != expected {
		return ErrStorageFormat
	}
	configs, err := s.scalar("SELECT count(*) FROM direct_issue_config")
	if err != nil {
		return err
	}
	if configs == int64(0) {
		if expected != 0 {
			return ErrStorageFormat
		}
		return nil
	}
	if configs != int64(1) {
		return ErrStorageFormat
	}
	active, err := s.scalar("SELECT count(*) FROM issuance WHERE state<>2")
	if err != nil {
		return err
	}
	activeCount, ok := active.(int64)
	if !ok || activeCount < 0 || activeCount > expected {
		return ErrStorageFormat
	}
	return s.readOne("SELECT rows,state_bytes,credit,last_upper,length(configuration) FROM direct_issue_config WHERE id=1", 5, func(v []driver.Value) error {
		rows, ok := v[0].(int64)
		size, sok := v[1].(int64)
		_, ce := readSQLiteUint(v[2])
		_, te := readSQLiteUint(v[3])
		length, lok := v[4].(int64)
		if !ok || rows != activeCount || !sok || size < 0 || ce != nil || te != nil || !lok || length < 1 || length > 8192 {
			return ErrStorageFormat
		}
		return nil
	})
}
