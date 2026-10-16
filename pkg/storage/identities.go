package storage

import (
	"database/sql"
	"time"

	"monito/pkg/identity"
)

type identityQuery interface {
	Query(string, ...any) (*sql.Rows, error)
}

func readIdentities(q identityQuery) ([]*identity.AppIdentity, map[string]int64, error) {
	rows, err := q.Query(`SELECT id, app_key, display_name, category, icon_or_type,
        COALESCE(executable_path,''), COALESCE(cgroup_path,''), first_seen, last_seen FROM app_identities`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var result []*identity.AppIdentity
	ids := make(map[string]int64)
	for rows.Next() {
		var ident identity.AppIdentity
		var id, first, last int64
		if err := rows.Scan(&id, &ident.AppKey, &ident.DisplayName, &ident.Category, &ident.IconOrType, &ident.ExecutablePath, &ident.CgroupPath, &first, &last); err != nil {
			return nil, nil, err
		}
		ident.FirstSeen, ident.LastSeen = time.Unix(first, 0), time.Unix(last, 0)
		ids[ident.AppKey] = id
		result = append(result, &ident)
	}
	return result, ids, rows.Err()
}

func (s *Storage) ListIdentities() ([]*identity.AppIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	identities, _, err := readIdentities(s.db)
	return identities, err
}

// Reconcile aliases without rewriting or deleting any traffic. If a second
// executable with the same basename appears, an ambiguous alias is revoked and
// the original records are still available for separate accounting.
func reconcileAliases(tx *sql.Tx) error {
	identities, ids, err := readIdentities(tx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM app_aliases`); err != nil {
		return err
	}
	for _, ident := range identities {
		key := identity.MatchFallback(ident.AppKey, identities)
		if key != "" {
			if _, err := tx.Exec(`INSERT INTO app_aliases(alias_id,canonical_id) VALUES(?,?)`, ids[ident.AppKey], ids[key]); err != nil {
				return err
			}
		}
		category := identity.CategoryForIdentity(ident)
		if category == "unknown" && ident.Category == "desktop_app" {
			category = "desktop_app"
		}

		icon := "system"
		switch category {
		case "cli_tool":
			icon = "cli"
		case "web_browser":
			icon = "browser"
		case "desktop_app":
			icon = "app"
		case "system_service":
			icon = "service"
		}
		if _, err := tx.Exec(`UPDATE app_identities SET category=?,icon_or_type=? WHERE id=?`, category, icon, ids[ident.AppKey]); err != nil {
			return err
		}
	}
	return nil
}

// CanonicalKeys is also used to sum live rates for command-name aliases.
func (s *Storage) CanonicalKeys() (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT original.app_key, canonical.app_key FROM app_aliases x
        JOIN app_identities original ON original.id=x.alias_id
        JOIN app_identities canonical ON canonical.id=x.canonical_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := make(map[string]string)
	for rows.Next() {
		var alias, canonical string
		if err := rows.Scan(&alias, &canonical); err != nil {
			return nil, err
		}
		keys[alias] = canonical
	}
	return keys, rows.Err()
}
