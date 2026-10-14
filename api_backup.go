package main

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func (a *API) registerBackup(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/backups", a.auth(a.backupList))
	mux.HandleFunc("POST /api/backups", a.auth(a.backupCreate))
	mux.HandleFunc("POST /api/backups/restore", a.auth(a.backupRestoreUpload))
	mux.HandleFunc("GET /api/backups/{name}", a.auth(a.backupDownload))
	mux.HandleFunc("POST /api/backups/{name}/restore", a.auth(a.backupRestoreNamed))
	mux.HandleFunc("DELETE /api/backups/{name}", a.auth(a.backupDelete))
}

func (a *API) backupList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"backups":   ListBackups(a.cfg),
		"encrypted": a.cfg.BackupPassword != "",
		"interval":  a.cfg.BackupInterval.String(),
		"keep":      a.cfg.BackupKeep,
		"dir":       a.cfg.backupDir(),
	})
}

func (a *API) backupCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	info, err := CreateBackup(ctx, a.cfg, a.store, "")
	if err != nil {
		apiErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"backup": info})
}

func (a *API) backupDownload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	b, err := ReadBackupFile(a.cfg, name)
	if err != nil {
		a.forumFail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Write(b)
}

func (a *API) backupDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validBackupName(name) {
		apiErr(w, 404, ErrNotFound)
		return
	}
	if err := os.Remove(filepath.Join(a.cfg.backupDir(), name)); err != nil {
		apiErr(w, 404, ErrNotFound)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) backupRestoreNamed(w http.ResponseWriter, r *http.Request) {
	b, err := ReadBackupFile(a.cfg, r.PathValue("name"))
	if err != nil {
		a.forumFail(w, err)
		return
	}
	a.doRestore(w, r, b)
}

func (a *API) backupRestoreUpload(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, backupMaxSize))
	if err != nil || len(b) == 0 {
		apiErr(w, 400, errors.New("файл не получен или слишком большой"))
		return
	}
	a.doRestore(w, r, b)
}

func (a *API) doRestore(w http.ResponseWriter, r *http.Request, b []byte) {
	if err := RestoreFromData(r.Context(), a.cfg, a.store, b); err != nil {
		apiErr(w, 400, err)
		return
	}
	// the gateway is rebuilt from the database by the next reconcile; force an immediate refresh of subscriptions' state
	select {
	case a.refresh <- struct{}{}:
	default:
	}
	writeJSON(w, 200, map[string]any{"ok": true, "restored_at": time.Now().UTC()})
}
