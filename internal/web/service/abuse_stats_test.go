package service

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

func TestAbuseAccessEventExtractsAccountAndBlockedTarget(t *testing.T) {
	now := time.Now()
	line := now.Local().Format("2006/01/02 15:04:05.000000") +
		" from tcp:203.0.113.12:54321 accepted tcp:example.org:443 [in -> blocked] email: member1"
	_, _, email, source, target, network, port, blocked, ok := accessEvent(line, now)
	if !ok || email != "member1" || source != "203.0.113.12" || target != hashText("example.org") || network != "tcp" || port != 443 || blocked != 1 {
		t.Fatalf("unexpected access event: ok=%v email=%q source=%q target=%q network=%q port=%d blocked=%d", ok, email, source, target, network, port, blocked)
	}
}

func TestAbuseScanLeavesPartialLineForNextPoll(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE abuse_events (
		id TEXT PRIMARY KEY, ts INTEGER, email TEXT, source_ip TEXT,
		target_hash TEXT, network TEXT, port INTEGER, blocked INTEGER)`); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	line := now.Local().Format("2006/01/02 15:04:05.000000") +
		" from tcp:203.0.113.12:54321 accepted tcp:example.org:443 [in -> direct] email: member1"
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	consumed, err := scanAbuseLines(strings.NewReader(line+"\n"+line[:20]), tx, now)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != int64(len(line)+1) {
		t.Fatalf("consumed %d bytes, want %d", consumed, len(line)+1)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM abuse_events`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("got %d complete events, err=%v", count, err)
	}
}
