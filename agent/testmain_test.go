package agent

import (
	"database/sql"
	"os"
	"testing"

	"github.com/Rehaan15790/belphegor/db"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestMain acquires a PostgreSQL advisory lock (7337741002) for the entire
// agent test suite so cross-package DELETE cleanup races with db/server
// packages are avoided when running `go test ./...`.
func TestMain(m *testing.M) {
	useThrowawayDB()
	dsn, _, err := db.DSN()
	if err != nil {
		os.Exit(m.Run())
	}
	conn, err := sql.Open("pgx", dsn)
	if err != nil || conn.Ping() != nil {
		os.Exit(m.Run())
	}
	defer conn.Close()
	if _, err := conn.Exec(`SELECT pg_advisory_lock(7337741002)`); err != nil {
		os.Exit(m.Run())
	}
	defer conn.Exec(`SELECT pg_advisory_unlock(7337741002)`) //nolint:errcheck
	os.Exit(m.Run())
}

// useThrowawayDB points the tests at BELPHEGOR_TEST_PG_DSN. They delete and rewrite rows, so they
// must never reach the operator's configured database; without the variable they skip.
func useThrowawayDB() {
	os.Setenv("BELPHEGOR_PG_DSN", os.Getenv("BELPHEGOR_TEST_PG_DSN"))
	os.Setenv("BELPHEGOR_CONFIG", os.DevNull)
}
