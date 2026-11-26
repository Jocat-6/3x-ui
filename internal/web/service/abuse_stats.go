package service

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"

	_ "github.com/mattn/go-sqlite3"
)

const abuseRetention = 14 * 24 * time.Hour

var abuseCollectMu sync.Mutex

type AbuseAccount struct {
	Email          string `json:"email"`
	Connections    int64  `json:"connections"`
	Blocked        int64  `json:"blocked"`
	UniqueTargets  int64  `json:"uniqueTargets"`
	SourceIPs      int64  `json:"sourceIps"`
	LastSeen       int64  `json:"lastSeen"`
	CumulativeUp   int64  `json:"cumulativeUp"`
	CumulativeDown int64  `json:"cumulativeDown"`
	WindowUp       int64  `json:"windowUp"`
	WindowDown     int64  `json:"windowDown"`
}

type AbuseTrend struct {
	Hour        int64 `json:"hour"`
	Connections int64 `json:"connections"`
	Blocked     int64 `json:"blocked"`
}

type AbuseSource struct {
	IP          string `json:"ip"`
	Users       string `json:"users"`
	Connections int64  `json:"connections"`
	LastSeen    int64  `json:"lastSeen"`
}

type AbusePort struct {
	Network     string `json:"network"`
	Port        int    `json:"port"`
	Connections int64  `json:"connections"`
}

type AbuseBandwidthPoint struct {
	Second   int64   `json:"second"`
	UpMbps   float64 `json:"upMbps"`
	DownMbps float64 `json:"downMbps"`
}

type AbuseSummary struct {
	WindowHours  int            `json:"windowHours"`
	GeneratedAt  int64          `json:"generatedAt"`
	LogEnabled   bool           `json:"logEnabled"`
	StatsEnabled bool           `json:"statsEnabled"`
	Connections  int64          `json:"connections"`
	Blocked      int64          `json:"blocked"`
	Accounts     []AbuseAccount `json:"accounts"`
	Trend        []AbuseTrend   `json:"trend"`
	Sources      []AbuseSource  `json:"sources"`
	Ports        []AbusePort    `json:"ports"`
}

func abuseDBPath() string {
	return filepath.Join(config.GetDBFolderPath(), "abuse-stats.db")
}

func openAbuseDB() (*sql.DB, error) {
	path := abuseDBPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite3", path+"?_busy_timeout=5000&_journal_mode=WAL")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS abuse_events (
			id TEXT PRIMARY KEY, ts INTEGER NOT NULL, email TEXT NOT NULL,
			source_ip TEXT NOT NULL, target_hash TEXT NOT NULL,
			network TEXT NOT NULL, port INTEGER NOT NULL, blocked INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS abuse_events_ts ON abuse_events(ts)`,
		`CREATE INDEX IF NOT EXISTS abuse_events_email_ts ON abuse_events(email, ts)`,
		`CREATE TABLE IF NOT EXISTS abuse_cursor (
			path TEXT PRIMARY KEY, offset INTEGER NOT NULL, prefix_hash TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS abuse_seen_files (
			file_key TEXT PRIMARY KEY, observed_at INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS abuse_traffic_clock (
			id INTEGER PRIMARY KEY CHECK(id=1), ts INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS abuse_traffic_samples (
			ts INTEGER NOT NULL, email TEXT NOT NULL, up INTEGER NOT NULL, down INTEGER NOT NULL, seconds INTEGER NOT NULL DEFAULT 5,
			PRIMARY KEY(ts,email))`,
		`CREATE INDEX IF NOT EXISTS abuse_traffic_samples_ts ON abuse_traffic_samples(ts)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return db, nil
}

func hashText(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func splitLogAddress(value string) (string, int, string, bool) {
	network, remainder, ok := strings.Cut(value, ":")
	if !ok || (network != "tcp" && network != "udp") {
		return "", 0, "", false
	}
	host, rawPort, err := net.SplitHostPort(remainder)
	if err != nil {
		return "", 0, "", false
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, "", false
	}
	return strings.ToLower(host), port, network, true
}

func accessEvent(line string, now time.Time) (id string, ts int64, email, sourceIP, targetHash, network string, port, blocked int, ok bool) {
	entry := parseAccessLogFields(line)
	if entry.DateTime.IsZero() || entry.Email == "" || entry.ToAddress == "" || entry.FromAddress == "" {
		return
	}
	if entry.DateTime.Before(now.Add(-abuseRetention)) || entry.DateTime.After(now.Add(time.Minute)) {
		return
	}
	source := entry.FromAddress
	if strings.HasPrefix(source, "tcp:") || strings.HasPrefix(source, "udp:") {
		source = source[4:]
	}
	host, _, err := net.SplitHostPort(source)
	if err != nil {
		return
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return
	}
	target, targetPort, targetNetwork, valid := splitLogAddress(entry.ToAddress)
	if !valid {
		return
	}
	id = hashText(line)
	ts = entry.DateTime.Unix()
	email = entry.Email
	sourceIP = addr.Unmap().String()
	targetHash = hashText(target)
	network = targetNetwork
	port = targetPort
	if entry.Outbound == "blocked" {
		blocked = 1
	}
	ok = true
	return
}

func scanAbuseLines(reader io.Reader, tx *sql.Tx, now time.Time) (int64, error) {
	buffer := bufio.NewReader(reader)
	var consumed int64
	for {
		line, err := buffer.ReadString('\n')
		if errors.Is(err, io.EOF) && len(line) > 0 {
			break // Leave a partial line for the next collection.
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return consumed, err
		}
		if len(line) == 0 {
			break
		}
		consumed += int64(len(line))
		if len(line) <= 16384 {
			id, ts, email, source, target, network, port, blocked, ok := accessEvent(strings.TrimSpace(line), now)
			if ok {
				if _, err := tx.Exec(`INSERT OR IGNORE INTO abuse_events
					(id,ts,email,source_ip,target_hash,network,port,blocked) VALUES (?,?,?,?,?,?,?,?)`,
					id, ts, email, source, target, network, port, blocked); err != nil {
					return consumed, err
				}
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	return consumed, nil
}

func collectRotatedAbuseFile(db *sql.DB, path string, info os.FileInfo, now time.Time) error {
	if info.ModTime().Before(now.Add(-abuseRetention)) {
		return nil
	}
	key := fmt.Sprintf("%s:%d:%d", path, info.Size(), info.ModTime().UnixNano())
	var exists int
	if err := db.QueryRow(`SELECT 1 FROM abuse_seen_files WHERE file_key=?`, key).Scan(&exists); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	var reader io.Reader = file
	if strings.HasSuffix(path, ".gz") {
		archive, err := gzip.NewReader(file)
		if err != nil {
			return err
		}
		defer archive.Close()
		reader = archive
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := scanAbuseLines(reader, tx, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO abuse_seen_files(file_key,observed_at) VALUES (?,?)`, key, now.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func collectCurrentAbuseFile(db *sql.DB, path string, now time.Time) error {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	first := make([]byte, 128)
	n, err := file.ReadAt(first, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	prefixHash := hashText(string(first[:n]))
	var offset int64
	var previousHash string
	err = db.QueryRow(`SELECT offset,prefix_hash FROM abuse_cursor WHERE path=?`, path).Scan(&offset, &previousHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if offset > info.Size() || previousHash != prefixHash {
		offset = 0
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	consumed, err := scanAbuseLines(file, tx, now)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO abuse_cursor(path,offset,prefix_hash) VALUES (?,?,?)
		ON CONFLICT(path) DO UPDATE SET offset=excluded.offset,prefix_hash=excluded.prefix_hash`,
		path, offset+consumed, prefixHash); err != nil {
		return err
	}
	return tx.Commit()
}

func collectAbuseStatsAt(db *sql.DB, path string, now time.Time) error {
	paths, err := filepath.Glob(path + ".*")
	if err != nil {
		return err
	}
	sort.Strings(paths)
	for _, rotated := range paths {
		if !strings.HasSuffix(rotated, ".gz") && !strings.HasSuffix(rotated, ".1") {
			continue
		}
		info, err := os.Stat(rotated)
		if err != nil {
			continue
		}
		if err := collectRotatedAbuseFile(db, rotated, info, now); err != nil {
			return err
		}
	}
	if err := collectCurrentAbuseFile(db, path, now); err != nil {
		return err
	}
	_, err = db.Exec(`DELETE FROM abuse_events WHERE ts < ?`, now.Add(-abuseRetention).Unix())
	if err != nil {
		return err
	}
	_, err = db.Exec(`DELETE FROM abuse_seen_files WHERE observed_at < ?`, now.Add(-abuseRetention).Unix())
	if err != nil {
		return err
	}
	if _, err = db.Exec(`DELETE FROM abuse_traffic_samples WHERE ts < ?`, now.Add(-abuseRetention).Unix()); err != nil {
		return err
	}
	return nil
}

// RecordAbuseTraffic records the deltas from Xray's five-second traffic poll.
func RecordAbuseTraffic(rows []*xray.ClientTraffic) error {
	abuseCollectMu.Lock()
	defer abuseCollectMu.Unlock()
	enabled, err := (&SettingService{}).GetAbuseStatsEnable()
	if err != nil || !enabled {
		return err
	}
	db, err := openAbuseDB()
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	seconds := int64(5)
	var previous int64
	if err := tx.QueryRow(`SELECT ts FROM abuse_traffic_clock WHERE id=1`).Scan(&previous); err == nil {
		if elapsed := now - previous; elapsed > 0 && elapsed <= 30 {
			seconds = elapsed
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	for _, row := range rows {
		if row == nil || row.Email == "" || row.Up+row.Down <= 0 {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO abuse_traffic_samples(ts,email,up,down,seconds) VALUES (?,?,?,?,?)
			ON CONFLICT(ts,email) DO UPDATE SET up=up+excluded.up,down=down+excluded.down`, now, row.Email, row.Up, row.Down, seconds); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO abuse_traffic_clock(id,ts) VALUES (1,?) ON CONFLICT(id) DO UPDATE SET ts=excluded.ts`, now); err != nil {
		return err
	}
	return tx.Commit()
}

// InitializeAbuseStats starts a new recording window without importing old logs.
func InitializeAbuseStats() error {
	abuseCollectMu.Lock()
	defer abuseCollectMu.Unlock()
	path, err := xray.GetAccessLogPath()
	if err != nil {
		return err
	}
	db, err := openAbuseDB()
	if err != nil {
		return err
	}
	defer db.Close()
	for _, table := range []string{"abuse_events", "abuse_cursor", "abuse_seen_files", "abuse_traffic_clock", "abuse_traffic_samples"} {
		if _, err := db.Exec(`DELETE FROM ` + table); err != nil {
			return err
		}
	}
	if info, err := os.Stat(path); err == nil {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		first := make([]byte, 128)
		n, err := file.ReadAt(first, 0)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if _, err := db.Exec(`INSERT INTO abuse_cursor(path,offset,prefix_hash) VALUES (?,?,?)`, path, info.Size(), hashText(string(first[:n]))); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	paths, err := filepath.Glob(path + ".*")
	if err != nil {
		return err
	}
	for _, rotated := range paths {
		info, err := os.Stat(rotated)
		if err != nil {
			continue
		}
		key := fmt.Sprintf("%s:%d:%d", rotated, info.Size(), info.ModTime().UnixNano())
		if _, err := db.Exec(`INSERT OR IGNORE INTO abuse_seen_files(file_key,observed_at) VALUES (?,?)`, key, time.Now().Unix()); err != nil {
			return err
		}
	}
	return nil
}

// CollectAbuseStats ingests only new access-log lines; a hashed line ID avoids
// duplicates when logrotate copies the active file into a numbered archive.
func CollectAbuseStats() error {
	abuseCollectMu.Lock()
	defer abuseCollectMu.Unlock()
	enabled, err := (&SettingService{}).GetAbuseStatsEnable()
	if err != nil || !enabled {
		return err
	}
	path, err := xray.GetAccessLogPath()
	if err != nil || path == "" || path == "none" {
		return err
	}
	db, err := openAbuseDB()
	if err != nil {
		return err
	}
	defer db.Close()
	return collectAbuseStatsAt(db, path, time.Now())
}

func GetAbuseSummary(hours int) (*AbuseSummary, error) {
	if hours != 24 && hours != 168 {
		return nil, fmt.Errorf("unsupported window")
	}
	path, err := xray.GetAccessLogPath()
	if err != nil {
		return nil, err
	}
	result := &AbuseSummary{
		WindowHours: hours, GeneratedAt: time.Now().Unix(),
		LogEnabled: path != "" && path != "none",
		Accounts:   []AbuseAccount{}, Trend: []AbuseTrend{},
		Sources: []AbuseSource{}, Ports: []AbusePort{},
	}
	result.StatsEnabled, err = (&SettingService{}).GetAbuseStatsEnable()
	if err != nil {
		return nil, err
	}
	if !result.LogEnabled || !result.StatsEnabled {
		return result, nil
	}
	if err := CollectAbuseStats(); err != nil {
		return nil, err
	}
	db, err := openAbuseDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	rows, err := db.Query(`SELECT email,COUNT(*),SUM(blocked),COUNT(DISTINCT target_hash),
		COUNT(DISTINCT source_ip),MAX(ts) FROM abuse_events WHERE ts>=? GROUP BY email ORDER BY COUNT(*) DESC`, since)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var item AbuseAccount
		if err := rows.Scan(&item.Email, &item.Connections, &item.Blocked, &item.UniqueTargets, &item.SourceIPs, &item.LastSeen); err != nil {
			rows.Close()
			return nil, err
		}
		result.Connections += item.Connections
		result.Blocked += item.Blocked
		result.Accounts = append(result.Accounts, item)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if panelDB := database.GetDB(); panelDB != nil {
		var traffic []struct {
			Email string
			Up    int64
			Down  int64
		}
		if err := panelDB.Table("client_traffics").Select("email, SUM(up) AS up, SUM(down) AS down").Group("email").Scan(&traffic).Error; err == nil {
			byEmail := make(map[string]int)
			for index, account := range result.Accounts {
				byEmail[account.Email] = index
			}
			for _, item := range traffic {
				index, ok := byEmail[item.Email]
				if !ok {
					index = len(result.Accounts)
					byEmail[item.Email] = index
					result.Accounts = append(result.Accounts, AbuseAccount{Email: item.Email})
				}
				result.Accounts[index].CumulativeUp = item.Up
				result.Accounts[index].CumulativeDown = item.Down
			}
		}
	}
	usageRows, err := db.Query(`SELECT email,SUM(up),SUM(down) FROM abuse_traffic_samples
		WHERE ts>=? GROUP BY email`, since)
	if err != nil {
		return nil, err
	}
	byEmail := make(map[string]int)
	for index, account := range result.Accounts {
		byEmail[account.Email] = index
	}
	for usageRows.Next() {
		var email string
		var up, down int64
		if err := usageRows.Scan(&email, &up, &down); err != nil {
			usageRows.Close()
			return nil, err
		}
		index, ok := byEmail[email]
		if !ok {
			index = len(result.Accounts)
			byEmail[email] = index
			result.Accounts = append(result.Accounts, AbuseAccount{Email: email})
		}
		result.Accounts[index].WindowUp = up
		result.Accounts[index].WindowDown = down
	}
	if err := usageRows.Close(); err != nil {
		return nil, err
	}
	trendRows, err := db.Query(`SELECT (ts/3600)*3600,COUNT(*),SUM(blocked) FROM abuse_events
		WHERE ts>=? GROUP BY (ts/3600)*3600 ORDER BY (ts/3600)*3600`, since)
	if err != nil {
		return nil, err
	}
	for trendRows.Next() {
		var item AbuseTrend
		if err := trendRows.Scan(&item.Hour, &item.Connections, &item.Blocked); err != nil {
			trendRows.Close()
			return nil, err
		}
		result.Trend = append(result.Trend, item)
	}
	if err := trendRows.Close(); err != nil {
		return nil, err
	}
	sourceRows, err := db.Query(`SELECT source_ip,GROUP_CONCAT(DISTINCT email),COUNT(*),MAX(ts)
		FROM abuse_events WHERE ts>=? GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT 50`, since)
	if err != nil {
		return nil, err
	}
	for sourceRows.Next() {
		var item AbuseSource
		if err := sourceRows.Scan(&item.IP, &item.Users, &item.Connections, &item.LastSeen); err != nil {
			sourceRows.Close()
			return nil, err
		}
		result.Sources = append(result.Sources, item)
	}
	if err := sourceRows.Close(); err != nil {
		return nil, err
	}
	portRows, err := db.Query(`SELECT network,port,COUNT(*) FROM abuse_events WHERE ts>=?
		GROUP BY network,port ORDER BY COUNT(*) DESC LIMIT 12`, since)
	if err != nil {
		return nil, err
	}
	for portRows.Next() {
		var item AbusePort
		if err := portRows.Scan(&item.Network, &item.Port, &item.Connections); err != nil {
			portRows.Close()
			return nil, err
		}
		result.Ports = append(result.Ports, item)
	}
	if err := portRows.Close(); err != nil {
		return nil, err
	}
	return result, nil
}

func GetAbuseBandwidth(email string) ([]AbuseBandwidthPoint, error) {
	if email == "" || len(email) > 256 {
		return nil, fmt.Errorf("invalid account")
	}
	enabled, err := (&SettingService{}).GetAbuseStatsEnable()
	if err != nil || !enabled {
		return []AbuseBandwidthPoint{}, err
	}
	db, err := openAbuseDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT ts,up,down,seconds FROM abuse_traffic_samples
		WHERE email=? AND ts>=? ORDER BY ts`, email, time.Now().Add(-time.Hour).Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []AbuseBandwidthPoint{}
	for rows.Next() {
		var point AbuseBandwidthPoint
		var up, down, seconds int64
		if err := rows.Scan(&point.Second, &up, &down, &seconds); err != nil {
			return nil, err
		}
		if seconds < 1 {
			seconds = 5
		}
		point.UpMbps = float64(up) * 8 / float64(seconds) / 1e6
		point.DownMbps = float64(down) * 8 / float64(seconds) / 1e6
		result = append(result, point)
	}
	return result, rows.Err()
}
