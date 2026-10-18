package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BraveRam/monito/pkg/identity"
)

func TestStorageRecordAndQuery(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "monito-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewStorage(dbPath)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	defer store.Close()

	ident1 := &identity.AppIdentity{
		AppKey:      "exec:/usr/bin/curl",
		DisplayName: "curl",
		Category:    "cli_tool",
		IconOrType:  "cli",
	}

	ident2 := &identity.AppIdentity{
		AppKey:      "flatpak:org.mozilla.firefox",
		DisplayName: "Firefox",
		Category:    "web_browser",
		IconOrType:  "browser",
	}

	records := []IngestionRecord{
		{
			Identity:   ident1,
			Category:   2, // External
			BytesIn:    1000,
			BytesOut:   500,
			PacketsIn:  10,
			PacketsOut: 5,
		},
		{
			Identity:   ident2,
			Category:   2, // External
			BytesIn:    50000,
			BytesOut:   2000,
			PacketsIn:  100,
			PacketsOut: 30,
		},
	}

	if err := store.RecordUsage(records, time.UTC); err != nil {
		t.Fatalf("RecordUsage failed: %v", err)
	}

	today := time.Now().UTC().Format("2006-01-02")

	// Verify DaySummary
	summary, err := store.GetDaySummary(today)
	if err != nil {
		t.Fatalf("GetDaySummary failed: %v", err)
	}
	if summary.TotalBytesIn != 51000 {
		t.Errorf("expected 51000 bytes in, got %d", summary.TotalBytesIn)
	}
	if summary.TotalBytesOut != 2500 {
		t.Errorf("expected 2500 bytes out, got %d", summary.TotalBytesOut)
	}
	if summary.ActiveAppCount != 2 {
		t.Errorf("expected 2 active apps, got %d", summary.ActiveAppCount)
	}

	// Verify AppsForDay ranking
	apps, err := store.GetAppsForDay(today, "total")
	if err != nil {
		t.Fatalf("GetAppsForDay failed: %v", err)
	}
	if len(apps) != 2 {
		t.Fatalf("expected 2 apps, got %d", len(apps))
	}
	// Firefox should be first (52000 bytes total > 1500)
	if apps[0].Identity.DisplayName != "Firefox" {
		t.Errorf("expected first app to be Firefox, got %s", apps[0].Identity.DisplayName)
	}
	if apps[0].TotalBytes != 52000 {
		t.Errorf("expected 52000 total bytes for Firefox, got %d", apps[0].TotalBytes)
	}

	// Add more records for curl and verify delta summation
	moreRecords := []IngestionRecord{
		{
			Identity:   ident1,
			Category:   2,
			BytesIn:    2000,
			BytesOut:   1000,
			PacketsIn:  20,
			PacketsOut: 10,
		},
	}
	if err := store.RecordUsage(moreRecords, time.UTC); err != nil {
		t.Fatalf("second RecordUsage failed: %v", err)
	}

	appsAfter, _ := store.GetAppsForDay(today, "total")
	var curlRecord *TrafficRecord
	for i := range appsAfter {
		if appsAfter[i].Identity.AppKey == "exec:/usr/bin/curl" {
			curlRecord = &appsAfter[i]
			break
		}
	}
	if curlRecord == nil {
		t.Fatal("curl record not found")
	}
	if curlRecord.BytesIn != 3000 {
		t.Errorf("expected curl bytesIn to be 3000, got %d", curlRecord.BytesIn)
	}
	if curlRecord.BytesOut != 1500 {
		t.Errorf("expected curl bytesOut to be 1500, got %d", curlRecord.BytesOut)
	}
}

func TestRetentionPruning(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "monito-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewStorage(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Prune with 14 days should succeed without error
	deleted, err := store.PruneOldHistory(14)
	if err != nil {
		t.Fatalf("PruneOldHistory failed: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted rows on empty db, got %d", deleted)
	}
}

func TestHistoryWindowAndTrafficCategories(t *testing.T) {
	store, err := NewStorage(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ident := &identity.AppIdentity{AppKey: "test:external", DisplayName: "External app"}
	now := time.Now()
	record := IngestionRecord{Identity: ident, Category: 2, BytesIn: 100, ObservedAt: now}
	if err := store.RecordUsage([]IngestionRecord{record}, time.Local); err != nil {
		t.Fatal(err)
	}
	record.ObservedAt = now.AddDate(0, 0, -7)
	if err := store.RecordUsage([]IngestionRecord{record}, time.Local); err != nil {
		t.Fatal(err)
	}
	record.ObservedAt = now.AddDate(0, 0, -6)
	if err := store.RecordUsage([]IngestionRecord{record}, time.Local); err != nil {
		t.Fatal(err)
	}
	history, err := store.GetAppHistory(ident.AppKey, 7)
	if err != nil || len(history) != 2 {
		t.Fatalf("history=%+v err=%v", history, err)
	}
	apps, err := store.GetAppsForDay(now.Format("2006-01-02"), "total")
	if err != nil || len(apps) != 1 {
		t.Fatalf("apps=%+v err=%v", apps, err)
	}
	if apps[0].Category != 2 || apps[0].CategoryStr != "external" {
		t.Fatalf("wrong category: %+v", apps[0])
	}
	record.Category, record.ObservedAt = 0, now
	if err := store.RecordUsage([]IngestionRecord{record}, time.Local); err != nil {
		t.Fatal(err)
	}
	apps, err = store.GetAppsForDay(now.Format("2006-01-02"), "total")
	if err != nil || apps[0].Category != -1 || apps[0].CategoryStr != "mixed" || apps[0].TotalBytes != 200 {
		t.Fatalf("mixed categories must remain one app: %+v err=%v", apps, err)
	}
}

func TestAliasGroupingPreservesTotalsHistoryAndAmbiguity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aliases.db")
	store, err := NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	record := func(key string, bytes uint64) {
		t.Helper()
		ident := &identity.AppIdentity{AppKey: key, DisplayName: "gh", Category: "desktop_app"}
		if strings.HasPrefix(key, "exec:/") {
			ident.ExecutablePath = strings.TrimPrefix(key, "exec:")
		}
		if err := store.RecordUsage([]IngestionRecord{{Identity: ident, Category: 2, BytesIn: bytes}}, time.Local); err != nil {
			t.Fatal(err)
		}
	}
	record("exec:gh", 100)
	record("exec:short_lived:gh", 200)
	fallbacks, err := store.GetAppsForDay(time.Now().Format("2006-01-02"), "total")
	if err != nil || len(fallbacks) != 1 || fallbacks[0].TotalBytes != 300 {
		t.Fatalf("command-only groups=%+v err=%v", fallbacks, err)
	}
	record("exec:/usr/bin/gh", 300)
	today := time.Now().Format("2006-01-02")
	apps, err := store.GetAppsForDay(today, "total")
	if err != nil || len(apps) != 1 || apps[0].TotalBytes != 600 || apps[0].Identity.Category != "cli_tool" {
		t.Fatalf("grouped=%+v err=%v", apps, err)
	}
	for _, key := range []string{"exec:gh", "exec:short_lived:gh", "exec:/usr/bin/gh"} {
		history, err := store.GetAppHistory(key, 7)
		if err != nil || len(history) != 1 || history[0].TotalBytes != 600 {
			t.Fatalf("%s history=%+v err=%v", key, history, err)
		}
	}
	summary, err := store.GetDaySummary(today)
	if err != nil || summary.RecordedAppCount != 1 || summary.TotalBytes != 600 {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
	store.Close()
	store, err = NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	apps, err = store.GetAppsForDay(today, "total")
	if err != nil || len(apps) != 1 || apps[0].TotalBytes != 600 {
		t.Fatalf("restart=%+v err=%v", apps, err)
	}
	// Another distinct binary makes the basename ambiguous. Originals remain
	// intact, so the aliases can be revoked without moving/doubling any bytes.
	record("exec:/opt/other/gh", 400)
	apps, err = store.GetAppsForDay(today, "total")
	if err != nil || len(apps) != 4 {
		t.Fatalf("ambiguous groups=%+v err=%v", apps, err)
	}
	summary, err = store.GetDaySummary(today)
	if err != nil || summary.TotalBytes != 1000 {
		t.Fatalf("totals changed: %+v %v", summary, err)
	}
}

func TestLegacyFallbackRowsReconcileOnRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	store, err := NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { store.Close() }()
	for _, name := range []string{"node-MainThread", "npm exec rea-ag"} {
		for _, prefix := range []string{"exec:", "exec:short_lived:"} {
			ident := &identity.AppIdentity{AppKey: prefix + name, DisplayName: name, Category: "desktop_app"}
			if err := store.RecordUsage([]IngestionRecord{{Identity: ident, Category: 0, BytesIn: 100, BytesOut: 50}}, time.Local); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Simulate a database from before alias reconciliation and classification.
	if _, err := store.db.Exec(`DELETE FROM app_aliases; UPDATE app_identities SET category='desktop_app',icon_or_type='app'`); err != nil {
		t.Fatal(err)
	}
	store.Close()
	store, err = NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	today := time.Now().Format("2006-01-02")
	apps, err := store.GetAppsForDay(today, "total")
	if err != nil || len(apps) != 2 {
		t.Fatalf("apps=%+v err=%v", apps, err)
	}
	for _, app := range apps {
		if app.TotalBytes != 300 || app.Identity.Category != "cli_tool" || app.Identity.IconOrType != "cli" {
			t.Errorf("wrong grouped row: %+v identity=%+v", app, app.Identity)
		}
		for _, prefix := range []string{"exec:", "exec:short_lived:"} {
			history, err := store.GetAppHistory(prefix+app.Identity.DisplayName, 7)
			if err != nil || len(history) != 1 || history[0].TotalBytes != 300 {
				t.Errorf("history=%+v err=%v", history, err)
			}
		}
	}
	keys, err := store.CanonicalKeys()
	if err != nil || keys["exec:short_lived:node-MainThread"] != "exec:node-MainThread" || keys["exec:short_lived:npm exec rea-ag"] != "exec:npm exec rea-ag" {
		t.Fatalf("live aliases=%v err=%v", keys, err)
	}
	summary, err := store.GetDaySummary(today)
	if err != nil || summary.TotalBytes != 600 || summary.RecordedAppCount != 2 {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
}

func TestAttributionIsIndependentOfTrafficCategory(t *testing.T) {
	store, err := NewStorage(filepath.Join(t.TempDir(), "coverage.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	records := []IngestionRecord{
		{Identity: &identity.AppIdentity{AppKey: "exec:/usr/bin/curl", DisplayName: "curl"}, Category: 3, BytesIn: 30},
		{Identity: &identity.AppIdentity{AppKey: "unknown:unattributed", DisplayName: "Unattributed"}, Category: 2, BytesIn: 70},
	}
	if err := store.RecordUsage(records, time.Local); err != nil {
		t.Fatal(err)
	}
	summary, err := store.GetDaySummary(time.Now().Format("2006-01-02"))
	if err != nil || summary.UnattributedBytes != 70 || summary.UnknownBytes != 30 || summary.RecordedAppCount != 1 {
		t.Fatalf("coverage=%+v err=%v", summary, err)
	}
}

// Filtering happens at read time so upgrades also correct old displayed totals.
func TestExternalViewsExcludeLocalHistory(t *testing.T) {
	store, err := NewStorage(filepath.Join(t.TempDir(), "scope.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	mixed := &identity.AppIdentity{AppKey: "exec:mixed", DisplayName: "mixed", Category: "cli_tool"}
	local := &identity.AppIdentity{AppKey: "exec:adb", DisplayName: "adb", Category: "cli_tool"}
	unknown := &identity.AppIdentity{AppKey: "unknown:unattributed", DisplayName: "Unattributed Traffic", Category: "unknown"}
	now := time.Now()
	records := []IngestionRecord{
		{Identity: mixed, Category: 2, BytesIn: 100, BytesOut: 20, PacketsIn: 3, PacketsOut: 2},
		{Identity: mixed, Category: 0, BytesIn: 9000, BytesOut: 9000},
		{Identity: mixed, Category: 1, BytesIn: 7000},
		{Identity: mixed, Category: 3, BytesOut: 5000},
		{Identity: local, Category: 0, BytesIn: 100000, BytesOut: 100000},
		{Identity: unknown, Category: 2, BytesOut: 5},
		{Identity: unknown, Category: 0, BytesOut: 9999},
	}
	if err := store.RecordUsage(records, time.Local); err != nil {
		t.Fatal(err)
	}
	day := now.Format("2006-01-02")
	summary, err := store.GetExternalDaySummary(day)
	if err != nil {
		t.Fatal(err)
	}
	if summary.TotalBytes != 125 || summary.TotalBytesIn != 100 || summary.TotalBytesOut != 25 || summary.ExternalBytes != 125 || summary.RecordedAppCount != 1 || summary.UnattributedBytes != 5 || summary.PrivateBytes != 0 || summary.LoopbackBytes != 0 || summary.UnknownBytes != 0 {
		t.Fatalf("external summary: %+v", summary)
	}
	apps, err := store.GetExternalAppsForDay(day, "total")
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 2 || apps[0].Identity.AppKey != mixed.AppKey || apps[0].TotalBytes != 120 || apps[0].Category != 2 || apps[0].PacketsIn != 3 || apps[0].PacketsOut != 2 {
		t.Fatalf("external apps: %+v", apps)
	}
	history, err := store.GetExternalAppHistory(mixed.AppKey, 7)
	if err != nil || len(history) != 1 || history[0].TotalBytes != 120 {
		t.Fatalf("external history: %+v %v", history, err)
	}
	history, err = store.GetExternalAppHistory(local.AppKey, 7)
	if err != nil || len(history) != 0 {
		t.Fatalf("local history leaked: %+v %v", history, err)
	}
	raw, err := store.GetDaySummary(day)
	if err != nil || raw.TotalBytes != 125+18000+7000+5000+200000+9999 {
		t.Fatalf("raw history changed: %+v %v", raw, err)
	}
}
