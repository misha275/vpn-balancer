package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestVersionConstMatchesFile(t *testing.T) {
	b, err := os.ReadFile("VERSION")
	if err != nil {
		t.Skip("no VERSION file")
	}
	if strings.TrimSpace(string(b)) != appVersion {
		t.Fatalf("VERSION=%q appVersion=%q", strings.TrimSpace(string(b)), appVersion)
	}
}

func TestBackupPacking(t *testing.T) {
	data := []byte(`{"format":"vpnb-backup","secret":"vless://x"}`)
	plain, err := packBackup(data, "")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := unpackBackup(plain, ""); err != nil || string(got) != string(data) {
		t.Fatalf("plain: %v %q", err, got)
	}
	enc, err := packBackup(data, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(enc), "vless") {
		t.Fatal("encrypted file leaks plain text")
	}
	if got, err := unpackBackup(enc, "pw"); err != nil || string(got) != string(data) {
		t.Fatalf("enc: %v %q", err, got)
	}
	if _, err := unpackBackup(enc, "bad"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, err := unpackBackup(enc, ""); err == nil {
		t.Fatal("encrypted file without password accepted")
	}
	enc[len(enc)-1] ^= 1
	if _, err := unpackBackup(enc, "pw"); err == nil {
		t.Fatal("tampered file accepted")
	}
}

func TestBackupNames(t *testing.T) {
	for _, n := range []string{"vpnb-backup-v3.6.0-20260101-000000.json.gz", "vpnb-backup-v3.6.0-20260101-000000.json.gz.enc"} {
		if !validBackupName(n) {
			t.Errorf("%s must be valid", n)
		}
	}
	for _, n := range []string{"../etc/passwd", "vpnb-backup-../x.json.gz", "a.json.gz", "vpnb-backup-x/y.json.gz", ""} {
		if validBackupName(n) {
			t.Errorf("%q must be invalid", n)
		}
	}
}

func TestBackupRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	cfg := &Config{BackupDir: t.TempDir(), BackupKeep: 2, BackupPassword: "pw"}
	acc, err := st.CreateAccount(ctx, "bk@example.com", "hash", 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddUser(ctx, "bk-plain"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SavePlan(ctx, Plan{Name: "bk-plan", Days: 30, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutSetting(ctx, "bk_key", json.RawMessage(`"v1"`)); err != nil {
		t.Fatal(err)
	}
	tid, err := st.CreateTopic(ctx, acc.ID, "bug", "backup topic", "some body text")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.BlockUser(ctx, "bk-plain", "ban", "тест"); err != nil {
		t.Fatal(err)
	}
	tokBefore, _ := st.AdminToken(ctx)
	info, err := CreateBackup(ctx, cfg, st, "")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Encrypted || !strings.Contains(info.Name, "v"+appVersion) {
		t.Fatalf("bad info %+v", info)
	}
	raw, _ := ReadBackupFile(cfg, info.Name)
	if strings.Contains(string(raw), "bk@example.com") {
		t.Fatal("encrypted backup leaks the e-mail")
	}

	// mutate
	st.pool.Exec(ctx, `DELETE FROM users WHERE name='bk-plain'`)
	st.pool.Exec(ctx, `DELETE FROM plans`)
	st.PutSetting(ctx, "bk_key", json.RawMessage(`"v2"`))
	st.PutSetting(ctx, "bk_extra", json.RawMessage(`1`))
	if _, err := st.AddUser(ctx, "bk-new"); err != nil {
		t.Fatal(err)
	}

	if err := RestoreFromData(ctx, cfg, st, raw); err != nil {
		t.Fatal(err)
	}
	us, _ := st.ListUsers(ctx)
	names := map[string]User{}
	for _, u := range us {
		names[u.Name] = u
	}
	if _, ok := names["bk-new"]; ok {
		t.Error("user created after the backup survived the restore")
	}
	if u, ok := names["bk-plain"]; !ok || u.BlockKind != "ban" || u.BlockReason != "тест" {
		t.Errorf("bk-plain not restored with its block: %+v", u)
	}
	if _, ok := names["bk@example.com"]; !ok {
		t.Error("account user missing")
	}
	var v string
	st.pool.QueryRow(ctx, `SELECT value #>> '{}' FROM settings WHERE key='bk_key'`).Scan(&v)
	if v != "v1" {
		t.Errorf("setting = %q, want v1", v)
	}
	var n int
	st.pool.QueryRow(ctx, `SELECT count(*) FROM settings WHERE key='bk_extra'`).Scan(&n)
	if n != 0 {
		t.Error("setting created after the backup survived")
	}
	st.pool.QueryRow(ctx, `SELECT count(*) FROM plans WHERE name='bk-plan'`).Scan(&n)
	if n != 1 {
		t.Error("plan not restored")
	}
	if _, p, err := st.GetTopic(ctx, tid, true); err != nil || len(p) != 1 {
		t.Errorf("forum not restored: %v %v", err, p)
	}
	if tok, _ := st.AdminToken(ctx); tok != tokBefore {
		t.Error("admin token changed by restore")
	}
	// the sequences continue after the restored ids
	if _, err := st.AddUser(ctx, "bk-after"); err != nil {
		t.Fatalf("insert after restore: %v", err)
	}
	// the safety copy exists and rotation keeps the newest
	found := false
	for _, b := range ListBackups(cfg) {
		if strings.Contains(b.Name, "-before-restore") {
			found = true
		}
	}
	if !found {
		t.Error("no safety copy before restore")
	}
	if err := RestoreFromData(ctx, cfg, st, []byte("garbage")); err == nil {
		t.Error("garbage accepted")
	}
}

func TestBackupRotation(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	cfg := &Config{BackupDir: t.TempDir(), BackupKeep: 2}
	for i := 0; i < 4; i++ {
		if _, err := CreateBackup(ctx, cfg, st, string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(ListBackups(cfg)); n != 2 {
		t.Fatalf("kept %d, want 2", n)
	}
}

func TestBlockUser(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	acc, err := st.CreateAccount(ctx, "blk@example.com", "h", 5)
	if err != nil {
		t.Fatal(err)
	}
	has := func() bool {
		us, _ := st.EnabledUsers(ctx)
		for _, u := range us {
			if u.Name == "blk@example.com" {
				return true
			}
		}
		return false
	}
	if !has() {
		t.Fatal("new account must be active")
	}
	u0, _ := st.UserBySubToken(ctx, acc.SubToken)
	if u0 == nil {
		t.Fatal("no user by token")
	}
	if err := st.BlockUser(ctx, "blk@example.com", "bogus", ""); err == nil {
		t.Error("bad kind accepted")
	}
	if err := st.BlockUser(ctx, "nobody", "ban", ""); err == nil {
		t.Error("unknown user accepted")
	}
	if err := st.BlockUser(ctx, "blk@example.com", "unpaid", strings.Repeat("я", 301)); err == nil {
		t.Error("too long reason accepted")
	}
	if err := st.BlockUser(ctx, "blk@example.com", "unpaid", strings.Repeat("я", 300)); err != nil {
		t.Fatal(err)
	}
	if has() {
		t.Error("blocked user still in the gateway list")
	}
	if u, err := st.UserBySubToken(ctx, acc.SubToken); err == nil && u != nil && u.Active(time.Now()) {
		t.Error("blocked user's subscription still active")
	}
	us, _ := st.ListUsers(ctx)
	for _, u := range us {
		if u.Name == "blk@example.com" {
			if u.BlockKind != "unpaid" || len([]rune(u.BlockReason)) != 300 || u.BlockedAt == nil || u.Active(time.Now()) {
				t.Errorf("bad block state %+v", u)
			}
		}
	}
	// a payment lifts "unpaid"
	pl := Plan{ID: 0, Name: "p", Days: 10}
	p, err := st.CreatePayment(ctx, acc.ID, pl, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := st.MarkPaid(ctx, p.ID); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if !has() {
		t.Error("payment did not lift the unpaid block")
	}
	// a ban is not lifted by a payment and closes the login
	if err := st.BlockUser(ctx, "blk@example.com", "ban", "спам"); err != nil {
		t.Fatal(err)
	}
	p2, _ := st.CreatePayment(ctx, acc.ID, pl, "manual")
	st.MarkPaid(ctx, p2.ID)
	if has() {
		t.Error("payment lifted a ban")
	}
	a, _ := st.AccountByID(ctx, acc.ID)
	if a.BlockKind != "ban" || a.BlockReason != "спам" {
		t.Errorf("account view: %+v", a)
	}
	var blocked bool
	st.pool.QueryRow(ctx, `SELECT blocked FROM accounts WHERE id=$1`, acc.ID).Scan(&blocked)
	if !blocked {
		t.Error("ban must close the site login")
	}
	if err := st.UnblockUser(ctx, "blk@example.com"); err != nil {
		t.Fatal(err)
	}
	if !has() {
		t.Error("unblock did not restore access")
	}
}

func TestForumStore(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	acc, err := st.CreateAccount(ctx, "fr@example.com", "h", 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateTopic(ctx, acc.ID, "nope", "title ok", "body text"); err == nil {
		t.Error("bad kind accepted")
	}
	if _, err := st.CreateTopic(ctx, acc.ID, "bug", "ab", "body text"); err == nil {
		t.Error("short title accepted")
	}
	if _, err := st.CreateTopic(ctx, acc.ID, "bug", "title ok", strings.Repeat("x", forumBodyMax+1)); err == nil {
		t.Error("long body accepted")
	}
	id, err := st.CreateTopic(ctx, acc.ID, "bug", "Не работает\nподписка", "Подробности проблемы")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddPost(ctx, id, &acc.ID, false, "ещё одно"); err != nil {
		t.Fatal(err)
	}
	if err := st.AddPost(ctx, id, nil, true, "ответ поддержки"); err != nil {
		t.Fatal(err)
	}
	tp, posts, err := st.GetTopic(ctx, id, false)
	if err != nil || len(posts) != 3 || tp.Posts != 3 {
		t.Fatalf("%v %+v %+v", err, tp, posts)
	}
	if strings.Contains(tp.Author, "fr@") || strings.Contains(tp.Author, "example") {
		t.Errorf("author leaks identity: %q", tp.Author)
	}
	for _, p := range posts {
		if strings.Contains(p.Author, "@") {
			t.Errorf("post author leaks identity: %q", p.Author)
		}
	}
	// closed: users cannot write, staff can
	if err := st.TopicOp(ctx, id, "close"); err != nil {
		t.Fatal(err)
	}
	if err := st.AddPost(ctx, id, &acc.ID, false, "после закрытия"); err == nil {
		t.Error("user wrote to a closed topic")
	}
	if err := st.AddPost(ctx, id, nil, true, "staff after close"); err != nil {
		t.Errorf("staff cannot write to a closed topic: %v", err)
	}
	st.TopicOp(ctx, id, "open")
	// hidden post is not shown to users
	st.PostOp(ctx, posts[1].ID, "hide")
	if _, ps, _ := st.GetTopic(ctx, id, false); len(ps) != 3 { // 4 posts, 1 hidden
		t.Errorf("hidden post visible: %d", len(ps))
	}
	if _, ps, _ := st.GetTopic(ctx, id, true); len(ps) != 4 {
		t.Errorf("admin must see all: %d", len(ps))
	}
	// hidden topic: not in the user list, not readable
	st.TopicOp(ctx, id, "hide")
	if ts, _ := st.ListTopics(ctx, false, 50, 0); len(ts) != 0 {
		t.Error("hidden topic in the user list")
	}
	if _, _, err := st.GetTopic(ctx, id, false); err == nil {
		t.Error("hidden topic readable by a user")
	}
	if ts, _ := st.ListTopics(ctx, true, 50, 0); len(ts) != 1 {
		t.Error("admin must see the hidden topic")
	}
	if err := st.DeleteTopic(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := st.TopicOp(ctx, id, "close"); err == nil {
		t.Error("op on a deleted topic")
	}
}
