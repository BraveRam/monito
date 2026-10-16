package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BraveRam/monito/pkg/identity"
	"github.com/BraveRam/monito/pkg/storage"
)

func main() {
	home := os.Getenv("HOME")
	dbPath := filepath.Join(home, ".local/share/monito/monito.db")
	store, err := storage.NewStorage(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening storage: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	firefox := &identity.AppIdentity{
		AppKey:         "flatpak:org.mozilla.firefox",
		DisplayName:    "Firefox",
		Category:       "web_browser",
		IconOrType:     "browser",
		ExecutablePath: "/usr/bin/flatpak",
		CgroupPath:     "0::/user.slice/user-1000.slice/app-flatpak-org.mozilla.firefox-1234.scope",
	}

	chrome := &identity.AppIdentity{
		AppKey:         "exec:/opt/google/chrome/chrome",
		DisplayName:    "Google Chrome",
		Category:       "web_browser",
		IconOrType:     "browser",
		ExecutablePath: "/opt/google/chrome/chrome",
		CgroupPath:     "0::/user.slice/user-1000.slice/app-google-chrome.slice",
	}

	curl := &identity.AppIdentity{
		AppKey:         "exec:/usr/bin/curl",
		DisplayName:    "curl",
		Category:       "cli_tool",
		IconOrType:     "cli",
		ExecutablePath: "/usr/bin/curl",
	}

	resolved := &identity.AppIdentity{
		AppKey:         "systemd:systemd-resolved.service",
		DisplayName:    "systemd-resolved",
		Category:       "system_service",
		IconOrType:     "service",
		CgroupPath:     "0::/system.slice/systemd-resolved.service",
	}

	records := []storage.IngestionRecord{
		{
			Identity:   firefox,
			Category:   2, // External
			BytesIn:    45 * 1024 * 1024,
			BytesOut:   3 * 1024 * 1024,
			PacketsIn:  32000,
			PacketsOut: 15000,
		},
		{
			Identity:   chrome,
			Category:   2, // External
			BytesIn:    28 * 1024 * 1024,
			BytesOut:   1800 * 1024,
			PacketsIn:  21000,
			PacketsOut: 9000,
		},
		{
			Identity:   curl,
			Category:   2, // External
			BytesIn:    5 * 1024 * 1024,
			BytesOut:   512 * 1024,
			PacketsIn:  3500,
			PacketsOut: 1200,
		},
		{
			Identity:   resolved,
			Category:   1, // Private/DNS
			BytesIn:    420 * 1024,
			BytesOut:   280 * 1024,
			PacketsIn:  1200,
			PacketsOut: 1200,
		},
	}

	if err := store.RecordUsage(records, time.Local); err != nil {
		fmt.Fprintf(os.Stderr, "Error recording sample usage: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Ingested sample test records into Monito SQLite database.")
}
