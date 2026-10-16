package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/BraveRam/monito/pkg/identity"
)

// TrafficRecord represents an aggregated usage record for an application
type TrafficRecord struct {
	AppID       int64                 `json:"app_id"`
	Identity    *identity.AppIdentity `json:"identity"`
	Category    int                   `json:"category"`
	CategoryStr string                `json:"category_str"`
	BytesIn     int64                 `json:"bytes_in"`
	BytesOut    int64                 `json:"bytes_out"`
	TotalBytes  int64                 `json:"total_bytes"`
	PacketsIn   int64                 `json:"packets_in"`
	PacketsOut  int64                 `json:"packets_out"`
}

// DaySummary aggregates total traffic for a given calendar day
type DaySummary struct {
	DayDate           string `json:"day_date"`
	TotalBytesIn      int64  `json:"total_bytes_in"`
	TotalBytesOut     int64  `json:"total_bytes_out"`
	TotalBytes        int64  `json:"total_bytes"`
	ExternalBytes     int64  `json:"external_bytes"`
	PrivateBytes      int64  `json:"private_bytes"`
	LoopbackBytes     int64  `json:"loopback_bytes"`
	UnknownBytes      int64  `json:"unknown_bytes"`
	ActiveAppCount    int    `json:"active_app_count"` // Deprecated: use recorded_app_count.
	RecordedAppCount  int    `json:"recorded_app_count"`
	UnattributedBytes int64  `json:"unattributed_bytes"`
}

// AppHistoryPoint represents usage on a single day for an app
type AppHistoryPoint struct {
	Date       string `json:"date"`
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
	TotalBytes int64  `json:"total_bytes"`
}

// Storage manages SQLite persistence and metrics storage
type Storage struct {
	mu sync.Mutex
	db *sql.DB
}

// NewStorage opens SQLite database, sets WAL mode, and applies migrations
func NewStorage(dbPath string) (*Storage, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=ON&_synchronous=NORMAL", dbPath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	// Optimize connection pooling for SQLite
	db.SetMaxOpenConns(1) // Avoid lock contention on writes
	db.SetMaxIdleConns(1)

	s := &Storage{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate db: %w", err)
	}

	return s, nil
}

func (s *Storage) migrate() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at DATETIME NOT NULL
		);
	`)
	if err != nil {
		return err
	}

	var currentVersion int
	_ = s.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&currentVersion)

	if currentVersion < 1 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		_, err = tx.Exec(`
			CREATE TABLE IF NOT EXISTS app_identities (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				app_key TEXT UNIQUE NOT NULL,
				display_name TEXT NOT NULL,
				category TEXT NOT NULL,
				icon_or_type TEXT NOT NULL,
				executable_path TEXT,
				cgroup_path TEXT,
				first_seen INTEGER NOT NULL,
				last_seen INTEGER NOT NULL
			);

			CREATE TABLE IF NOT EXISTS traffic_hourly (
				bucket_time INTEGER NOT NULL,
				app_id INTEGER NOT NULL REFERENCES app_identities(id),
				category INTEGER NOT NULL,
				bytes_in INTEGER NOT NULL DEFAULT 0,
				bytes_out INTEGER NOT NULL DEFAULT 0,
				packets_in INTEGER NOT NULL DEFAULT 0,
				packets_out INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY (bucket_time, app_id, category)
			);

			CREATE TABLE IF NOT EXISTS traffic_daily (
				day_date TEXT NOT NULL,
				app_id INTEGER NOT NULL REFERENCES app_identities(id),
				category INTEGER NOT NULL,
				bytes_in INTEGER NOT NULL DEFAULT 0,
				bytes_out INTEGER NOT NULL DEFAULT 0,
				packets_in INTEGER NOT NULL DEFAULT 0,
				packets_out INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY (day_date, app_id, category)
			);

			CREATE TABLE IF NOT EXISTS interface_hourly (
				bucket_time INTEGER NOT NULL,
				ifname TEXT NOT NULL,
				rx_bytes INTEGER NOT NULL DEFAULT 0,
				tx_bytes INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY (bucket_time, ifname)
			);

			CREATE INDEX IF NOT EXISTS idx_traffic_hourly_app ON traffic_hourly(app_id);
			CREATE INDEX IF NOT EXISTS idx_traffic_daily_app ON traffic_daily(app_id);
			CREATE INDEX IF NOT EXISTS idx_traffic_daily_day ON traffic_daily(day_date);

			INSERT INTO schema_migrations (version, applied_at) VALUES (1, CURRENT_TIMESTAMP);
		`)
		if err != nil {
			return fmt.Errorf("migration 1 failed: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return err
		}
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS app_aliases (
        alias_id INTEGER PRIMARY KEY REFERENCES app_identities(id),
        canonical_id INTEGER NOT NULL REFERENCES app_identities(id),
        CHECK(alias_id != canonical_id));
        INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(2,CURRENT_TIMESTAMP);`); err != nil {
		return err
	}
	if err := reconcileAliases(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// IngestionRecord represents an incoming usage delta mapped to an AppIdentity
type IngestionRecord struct {
	Identity   *identity.AppIdentity
	ObservedAt time.Time
	Category   int
	BytesIn    uint64
	BytesOut   uint64
	PacketsIn  uint64
	PacketsOut uint64
}

// RecordUsage writes aggregated flow deltas to SQLite inside an atomic transaction
func (s *Storage) RecordUsage(records []IngestionRecord, localLoc *time.Location) error {
	if len(records) == 0 {
		return nil
	}
	if localLoc == nil {
		localLoc = time.Local
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	nowUnix := now.Unix()

	// Statement to get or create app identity
	stmtGetApp, err := tx.Prepare(`SELECT id FROM app_identities WHERE app_key = ?`)
	if err != nil {
		return err
	}
	defer stmtGetApp.Close()

	stmtInsertApp, err := tx.Prepare(`
		INSERT INTO app_identities (app_key, display_name, category, icon_or_type, executable_path, cgroup_path, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmtInsertApp.Close()

	stmtUpdateAppSeen, err := tx.Prepare(`UPDATE app_identities SET last_seen = ?, display_name=?, category=?, icon_or_type=?,
        executable_path=CASE WHEN ? != '' THEN ? ELSE executable_path END,
        cgroup_path=CASE WHEN ? != '' THEN ? ELSE cgroup_path END WHERE id = ?`)
	if err != nil {
		return err
	}
	defer stmtUpdateAppSeen.Close()

	stmtHourly, err := tx.Prepare(`
		INSERT INTO traffic_hourly (bucket_time, app_id, category, bytes_in, bytes_out, packets_in, packets_out)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(bucket_time, app_id, category) DO UPDATE SET
			bytes_in = bytes_in + excluded.bytes_in,
			bytes_out = bytes_out + excluded.bytes_out,
			packets_in = packets_in + excluded.packets_in,
			packets_out = packets_out + excluded.packets_out
	`)
	if err != nil {
		return err
	}
	defer stmtHourly.Close()

	stmtDaily, err := tx.Prepare(`
		INSERT INTO traffic_daily (day_date, app_id, category, bytes_in, bytes_out, packets_in, packets_out)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(day_date, app_id, category) DO UPDATE SET
			bytes_in = bytes_in + excluded.bytes_in,
			bytes_out = bytes_out + excluded.bytes_out,
			packets_in = packets_in + excluded.packets_in,
			packets_out = packets_out + excluded.packets_out
	`)
	if err != nil {
		return err
	}
	defer stmtDaily.Close()

	appIDCache := make(map[string]int64)

	for _, rec := range records {
		if rec.BytesIn == 0 && rec.BytesOut == 0 {
			continue
		}

		appKey := rec.Identity.AppKey
		appID, ok := appIDCache[appKey]
		if !ok {
			err := stmtGetApp.QueryRow(appKey).Scan(&appID)
			if err == sql.ErrNoRows {
				res, err := stmtInsertApp.Exec(
					appKey,
					rec.Identity.DisplayName,
					rec.Identity.Category,
					rec.Identity.IconOrType,
					rec.Identity.ExecutablePath,
					rec.Identity.CgroupPath,
					nowUnix,
					nowUnix,
				)
				if err != nil {
					return fmt.Errorf("insert app %s: %w", appKey, err)
				}
				appID, _ = res.LastInsertId()
			} else if err != nil {
				return fmt.Errorf("query app %s: %w", appKey, err)
			} else {
				if _, err := stmtUpdateAppSeen.Exec(nowUnix, rec.Identity.DisplayName, rec.Identity.Category, rec.Identity.IconOrType,
					rec.Identity.ExecutablePath, rec.Identity.ExecutablePath, rec.Identity.CgroupPath, rec.Identity.CgroupPath, appID); err != nil {
					return err
				}
			}
			appIDCache[appKey] = appID
		}

		observed := rec.ObservedAt
		if observed.IsZero() {
			observed = now
		}
		hourBucket := observed.UTC().Truncate(time.Hour).Unix()
		dayDate := observed.In(localLoc).Format("2006-01-02")

		// Insert hourly
		_, err = stmtHourly.Exec(
			hourBucket,
			appID,
			rec.Category,
			int64(rec.BytesIn),
			int64(rec.BytesOut),
			int64(rec.PacketsIn),
			int64(rec.PacketsOut),
		)
		if err != nil {
			return fmt.Errorf("upsert hourly: %w", err)
		}

		// Insert daily
		_, err = stmtDaily.Exec(
			dayDate,
			appID,
			rec.Category,
			int64(rec.BytesIn),
			int64(rec.BytesOut),
			int64(rec.PacketsIn),
			int64(rec.PacketsOut),
		)
		if err != nil {
			return fmt.Errorf("upsert daily: %w", err)
		}
	}

	if err := reconcileAliases(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// RecordInterfaceStats records raw interface counters for reconciliation
func (s *Storage) RecordInterfaceStats(ifname string, rxBytes, txBytes uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	hourBucket := time.Now().UTC().Truncate(time.Hour).Unix()
	_, err := s.db.Exec(`
		INSERT INTO interface_hourly (bucket_time, ifname, rx_bytes, tx_bytes)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(bucket_time, ifname) DO UPDATE SET
			rx_bytes = excluded.rx_bytes,
			tx_bytes = excluded.tx_bytes
	`, hourBucket, ifname, int64(rxBytes), int64(txBytes))

	return err
}

// GetDaySummary returns aggregated day totals
func (s *Storage) GetDaySummary(dayDate string) (*DaySummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	row := s.db.QueryRow(`
		SELECT
			COALESCE(SUM(bytes_in), 0),
			COALESCE(SUM(bytes_out), 0),
			COALESCE(SUM(CASE WHEN d.category = 2 THEN bytes_in + bytes_out ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN d.category = 1 THEN bytes_in + bytes_out ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN d.category = 0 THEN bytes_in + bytes_out ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN d.category = 3 THEN bytes_in + bytes_out ELSE 0 END), 0),
			COUNT(DISTINCT CASE WHEN a.app_key NOT LIKE 'unknown:%' THEN a.id END),
            COALESCE(SUM(CASE WHEN a.app_key LIKE 'unknown:%' THEN bytes_in+bytes_out ELSE 0 END),0)
		FROM traffic_daily d
        LEFT JOIN app_aliases x ON x.alias_id=d.app_id
        JOIN app_identities a ON a.id=COALESCE(x.canonical_id,d.app_id)
		WHERE day_date = ?
	`, dayDate)

	summary := &DaySummary{DayDate: dayDate}
	err := row.Scan(
		&summary.TotalBytesIn,
		&summary.TotalBytesOut,
		&summary.ExternalBytes,
		&summary.PrivateBytes,
		&summary.LoopbackBytes,
		&summary.UnknownBytes,
		&summary.ActiveAppCount,
		&summary.UnattributedBytes,
	)
	if err != nil {
		return nil, err
	}
	summary.RecordedAppCount = summary.ActiveAppCount
	summary.TotalBytes = summary.TotalBytesIn + summary.TotalBytesOut
	return summary, nil
}

// GetAppsForDay returns ranked applications for a given day
func (s *Storage) GetAppsForDay(dayDate string, sortBy string) ([]TrafficRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	orderClause := "total_bytes DESC"
	switch sortBy {
	case "upload", "out":
		orderClause = "bytes_out DESC"
	case "download", "in":
		orderClause = "bytes_in DESC"
	case "name":
		orderClause = "a.display_name ASC"
	default:
		orderClause = "total_bytes DESC"
	}

	query := fmt.Sprintf(`
		SELECT
			a.id,
			a.app_key,
			a.display_name,
			a.category,
			a.icon_or_type,
			a.executable_path,
			a.cgroup_path,
			a.first_seen,
			a.last_seen,
			SUM(d.bytes_in) as bytes_in,
			SUM(d.bytes_out) as bytes_out,
			(SUM(d.bytes_in) + SUM(d.bytes_out)) as total_bytes,
			SUM(d.packets_in) as packets_in,
			SUM(d.packets_out) as packets_out,
            CASE WHEN COUNT(DISTINCT d.category) = 1 THEN MIN(d.category) ELSE -1 END
		FROM traffic_daily d
		LEFT JOIN app_aliases x ON x.alias_id=d.app_id
        JOIN app_identities a ON a.id=COALESCE(x.canonical_id,d.app_id)
		WHERE d.day_date = ?
		GROUP BY a.id
		ORDER BY %s
	`, orderClause)

	rows, err := s.db.Query(query, dayDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []TrafficRecord
	for rows.Next() {
		var r TrafficRecord
		var ident identity.AppIdentity
		var firstSeen, lastSeen int64

		err := rows.Scan(
			&r.AppID,
			&ident.AppKey,
			&ident.DisplayName,
			&ident.Category,
			&ident.IconOrType,
			&ident.ExecutablePath,
			&ident.CgroupPath,
			&firstSeen,
			&lastSeen,
			&r.BytesIn,
			&r.BytesOut,
			&r.TotalBytes,
			&r.PacketsIn,
			&r.PacketsOut,
			&r.Category,
		)
		if err != nil {
			return nil, err
		}

		switch r.Category {
		case 0:
			r.CategoryStr = "loopback"
		case 1:
			r.CategoryStr = "private"
		case 2:
			r.CategoryStr = "external"
		case 3:
			r.CategoryStr = "unknown"
		default:
			r.CategoryStr = "mixed"
		}
		ident.FirstSeen = time.Unix(firstSeen, 0)
		ident.LastSeen = time.Unix(lastSeen, 0)
		r.Identity = &ident
		records = append(records, r)
	}

	return records, rows.Err()
}

// GetAppHistory returns daily usage for an application over the past N days
func (s *Storage) GetAppHistory(appKey string, days int) ([]AppHistoryPoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
		SELECT
			d.day_date,
			SUM(d.bytes_in),
			SUM(d.bytes_out)
		FROM traffic_daily d
		LEFT JOIN app_aliases x ON x.alias_id=d.app_id
        JOIN app_identities a ON a.id=COALESCE(x.canonical_id,d.app_id)
		WHERE a.id=COALESCE(
            (SELECT canonical_id FROM app_aliases WHERE alias_id=(SELECT id FROM app_identities WHERE app_key=?)),
            (SELECT id FROM app_identities WHERE app_key=?))
            AND d.day_date >= ? AND d.day_date <= ?
		GROUP BY d.day_date
		ORDER BY d.day_date DESC
		LIMIT ?
	`
	if days < 1 || days > 365 {
		return nil, fmt.Errorf("days must be between 1 and 365")
	}
	today := time.Now().In(time.Local)
	cutoff := today.AddDate(0, 0, 1-days).Format("2006-01-02")
	rows, err := s.db.Query(query, appKey, appKey, cutoff, today.Format("2006-01-02"), days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []AppHistoryPoint
	for rows.Next() {
		var pt AppHistoryPoint
		if err := rows.Scan(&pt.Date, &pt.BytesIn, &pt.BytesOut); err != nil {
			return nil, err
		}
		pt.TotalBytes = pt.BytesIn + pt.BytesOut
		history = append(history, pt)
	}
	return history, rows.Err()
}

// PruneOldHistory removes fine-grained hourly history older than retentionDays
func (s *Storage) PruneOldHistory(retentionDays int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Unix()
	res, err := s.db.Exec(`DELETE FROM traffic_hourly WHERE bucket_time < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Close closes the database connection
func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
