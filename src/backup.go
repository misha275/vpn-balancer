package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/scrypt"
)

// appVersion is written into backup names and files (kept equal to the VERSION file; a test checks it).
const appVersion = "3.10.1"

const (
	backupFormat   = "vpnb-backup"
	backupMagicEnc = "VPNBENC1"
	backupMaxSize  = 512 << 20
)

// backupTables are the tables that hold the data of the service, in the order of foreign keys.
// Not included: nodes, checks, switches, metrics (rebuilt by the checks), web_sessions (people log in again),
// acme_cache (certificates are re-issued) and the admin token (belongs to the installation, not to the data).
var backupTables = []string{
	"plans", "ext_sources", "users", "accounts", "payments", "custom_nodes", "bundles", "bundle_nodes",
	"bundle_sources", "wg_server", "wg_peers", "traffic_hourly", "user_seen", "forum_topics", "forum_posts", "forum_files",
	"site_pages", "servers", "server_traffic", "server_traffic_hourly", "balance_ops", "promos", "promo_uses", "settings",
}

// backupBigTable is not put into a backup when it is larger than the limit (attachments of the forum may be gigabytes).
const backupFilesLimit = 256 << 20

var backupSerial = []string{"plans", "ext_sources", "users", "accounts", "payments", "custom_nodes", "bundles", "forum_topics", "forum_posts", "forum_files", "servers", "balance_ops"}

type backupFile struct {
	Format  string                     `json:"format"`
	Version string                     `json:"version"`
	Created time.Time                  `json:"created"`
	Tables  map[string]json.RawMessage `json:"tables"`
}

// BackupInfo describes one stored backup.
type BackupInfo struct {
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	Created   time.Time `json:"created"`
	Encrypted bool      `json:"encrypted"`
}

var backupNameRe = regexp.MustCompile(`^vpnb-backup-[A-Za-z0-9._-]+\.json\.gz(\.enc)?$`)

func validBackupName(n string) bool { return backupNameRe.MatchString(n) && !strings.Contains(n, "..") }

// ExportBackup makes a consistent snapshot of the data as JSON.
func (s *Store) ExportBackup(ctx context.Context) ([]byte, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	bf := backupFile{Format: backupFormat, Version: appVersion, Created: time.Now().UTC(), Tables: map[string]json.RawMessage{}}
	for _, t := range backupTables {
		if t == "forum_files" {
			var n int64
			if err := tx.QueryRow(ctx, `SELECT COALESCE(SUM(size),0) FROM forum_files`).Scan(&n); err == nil && n > backupFilesLimit {
				log.Printf("backup: attachments of the forum (%d MB) are larger than %d MB and are not included", n>>20, backupFilesLimit>>20)
				bf.Tables[t] = json.RawMessage("[]")
				continue
			}
		}
		q := `SELECT COALESCE(jsonb_agg(to_jsonb(t)),'[]'::jsonb) FROM ` + t + ` t`
		if t == "settings" {
			q += ` WHERE t.key <> 'admin_token'`
		}
		var raw []byte
		if err := tx.QueryRow(ctx, q).Scan(&raw); err != nil {
			return nil, fmt.Errorf("backup %s: %w", t, err)
		}
		bf.Tables[t] = raw
	}
	return json.Marshal(bf)
}

// RestoreBackup replaces the data with the contents of a backup, all or nothing.
func (s *Store) RestoreBackup(ctx context.Context, data []byte) error {
	var bf backupFile
	if err := json.Unmarshal(data, &bf); err != nil {
		return fmt.Errorf("это не резервная копия: %v", err)
	}
	if bf.Format != backupFormat {
		return errors.New("это не резервная копия vpn-balancer")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var del []string
	for _, t := range backupTables {
		if t != "settings" {
			del = append(del, t)
		}
	}
	if _, err := tx.Exec(ctx, `TRUNCATE `+strings.Join(del, ", ")+` RESTART IDENTITY CASCADE`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM settings WHERE key <> 'admin_token'`); err != nil {
		return err
	}
	for _, t := range backupTables {
		raw, ok := bf.Tables[t]
		if !ok || len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "[]" {
			continue
		}
		var rows []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &rows); err != nil {
			return fmt.Errorf("таблица %s: %v", t, err)
		}
		if len(rows) == 0 {
			continue
		}
		real := map[string]bool{}
		cr, err := tx.Query(ctx, `SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1`, t)
		if err != nil {
			return err
		}
		for cr.Next() {
			var c string
			cr.Scan(&c)
			real[c] = true
		}
		cr.Close()
		seen := map[string]bool{}
		var cols []string
		for _, r := range rows {
			for k := range r {
				if real[k] && !seen[k] {
					seen[k] = true
					cols = append(cols, k)
				}
			}
		}
		sort.Strings(cols)
		if len(cols) == 0 {
			continue
		}
		list := `"` + strings.Join(cols, `","`) + `"`
		q := `INSERT INTO ` + t + ` (` + list + `) SELECT ` + list + ` FROM jsonb_populate_recordset(null::` + t + `, $1::jsonb)`
		if t == "settings" {
			q += ` WHERE key <> 'admin_token'`
		}
		if _, err := tx.Exec(ctx, q, string(raw)); err != nil {
			return fmt.Errorf("таблица %s: %v", t, err)
		}
	}
	for _, t := range backupSerial {
		if _, err := tx.Exec(ctx, `SELECT setval(pg_get_serial_sequence('`+t+`','id'), COALESCE((SELECT MAX(id) FROM `+t+`),1), (SELECT MAX(id) FROM `+t+`) IS NOT NULL)`); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ---- packing: gzip, optionally AES-256-GCM with a key from a password (scrypt) ----

func packBackup(data []byte, password string) ([]byte, error) {
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	zw.Write(data)
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if password == "" {
		return zb.Bytes(), nil
	}
	salt, nonce := make([]byte, 16), make([]byte, 12)
	rand.Read(salt)
	rand.Read(nonce)
	gcm, err := backupGCM(password, salt)
	if err != nil {
		return nil, err
	}
	out := append([]byte(backupMagicEnc), salt...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, zb.Bytes(), []byte(backupMagicEnc)), nil
}

func backupGCM(password string, salt []byte) (cipher.AEAD, error) {
	key, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	blk, _ := aes.NewCipher(key)
	return cipher.NewGCM(blk)
}

func unpackBackup(raw []byte, password string) ([]byte, error) {
	if bytes.HasPrefix(raw, []byte(backupMagicEnc)) {
		if password == "" {
			return nil, errors.New("копия зашифрована: задайте backup_password в config.yaml")
		}
		h := len(backupMagicEnc)
		if len(raw) < h+16+12+16 {
			return nil, errors.New("файл повреждён")
		}
		salt, nonce, ct := raw[h:h+16], raw[h+16:h+28], raw[h+28:]
		gcm, err := backupGCM(password, salt)
		if err != nil {
			return nil, err
		}
		raw, err = gcm.Open(nil, nonce, ct, []byte(backupMagicEnc))
		if err != nil {
			return nil, errors.New("не удалось расшифровать: неверный backup_password или файл повреждён")
		}
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, errors.New("файл не похож на копию vpn-balancer")
	}
	return io.ReadAll(io.LimitReader(zr, backupMaxSize))
}

// ---- files in backup_dir ----

func (c *Config) backupDir() string {
	if c.BackupDir != "" {
		return c.BackupDir
	}
	return filepath.Join(c.WorkDir, "backups")
}

// CreateBackup writes a new backup file and removes the oldest ones beyond backup_keep.
func CreateBackup(ctx context.Context, cfg *Config, st *Store, tag string) (BackupInfo, error) {
	data, err := st.ExportBackup(ctx)
	if err != nil {
		return BackupInfo{}, err
	}
	packed, err := packBackup(data, cfg.BackupPassword)
	if err != nil {
		return BackupInfo{}, err
	}
	dir := cfg.backupDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return BackupInfo{}, err
	}
	name := fmt.Sprintf("vpnb-backup-v%s-%s%s.json.gz", appVersion, time.Now().UTC().Format("20060102-150405"), tag)
	if cfg.BackupPassword != "" {
		name += ".enc"
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p+".tmp", packed, 0o600); err != nil {
		return BackupInfo{}, err
	}
	if err := os.Rename(p+".tmp", p); err != nil {
		return BackupInfo{}, err
	}
	pruneBackups(cfg)
	fi, _ := os.Stat(p)
	return BackupInfo{Name: name, Size: fi.Size(), Created: fi.ModTime(), Encrypted: cfg.BackupPassword != ""}, nil
}

func ListBackups(cfg *Config) []BackupInfo {
	ents, _ := os.ReadDir(cfg.backupDir())
	out := []BackupInfo{}
	for _, e := range ents {
		if e.IsDir() || !validBackupName(e.Name()) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, BackupInfo{Name: e.Name(), Size: fi.Size(), Created: fi.ModTime(), Encrypted: strings.HasSuffix(e.Name(), ".enc")})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

func pruneBackups(cfg *Config) {
	keep := cfg.BackupKeep
	if keep <= 0 {
		keep = 14
	}
	l := ListBackups(cfg)
	n := 0
	for _, b := range l {
		if strings.Contains(b.Name, "-before-restore") {
			continue // safety copies are kept until removed by hand
		}
		n++
		if n > keep {
			os.Remove(filepath.Join(cfg.backupDir(), b.Name))
		}
	}
}

// RestoreFromData restores from the bytes of a backup file after making a safety copy of the current data.
func RestoreFromData(ctx context.Context, cfg *Config, st *Store, raw []byte) error {
	plain, err := unpackBackup(raw, cfg.BackupPassword)
	if err != nil {
		return err
	}
	var probe backupFile
	if err := json.Unmarshal(plain, &probe); err != nil || probe.Format != backupFormat {
		return errors.New("это не резервная копия vpn-balancer")
	}
	if _, err := CreateBackup(ctx, cfg, st, "-before-restore"); err != nil {
		return fmt.Errorf("не удалось сделать страховочную копию: %v", err)
	}
	return st.RestoreBackup(ctx, plain)
}

func ReadBackupFile(cfg *Config, name string) ([]byte, error) {
	if !validBackupName(name) {
		return nil, ErrNotFound
	}
	b, err := os.ReadFile(filepath.Join(cfg.backupDir(), name))
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	return b, err
}

// BackupLoop makes a backup every backup_interval (0 = off) and, if a password is set, sends it to Telegram.
func BackupLoop(ctx context.Context, cfg *Config, st *Store, notify *Notifier) {
	if cfg.BackupInterval <= 0 {
		return
	}
	last := time.Time{}
	if l := ListBackups(cfg); len(l) > 0 {
		last = l[0].Created
	}
	for {
		wait := time.Until(last.Add(cfg.BackupInterval))
		if wait < time.Minute {
			wait = time.Minute
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		bc, cancel := context.WithTimeout(ctx, 2*time.Minute)
		info, err := CreateBackup(bc, cfg, st, "")
		cancel()
		last = time.Now()
		if err != nil {
			log.Printf("backup: %v", err)
			notify.Notify("backup", "🔴 Не удалось сделать резервную копию: "+err.Error(), 6*time.Hour)
			continue
		}
		log.Printf("backup: %s (%d bytes)", info.Name, info.Size)
		if cfg.BackupTelegram && info.Encrypted {
			notify.SendFile(filepath.Join(cfg.backupDir(), info.Name), info.Name)
		}
	}
}
