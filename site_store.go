package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Storage of the public site: accounts, sessions, plans, payments and the certificate cache.

var (
	ErrNotFound   = errors.New("not found")
	ErrEmailTaken = errors.New("email is already registered")
)

// Account is a person who registered on the site. Every account owns one VPN user (the key, the period, the traffic).
type Account struct {
	ID        int64
	Email     string
	PassHash  string
	UserID    int64
	Blocked   bool
	Note      string
	Created   time.Time
	LastLogin *time.Time
	// the VPN user
	UserName string
	UUID     string
	SubToken string
	Expires  *time.Time
	Enabled  bool

	Subs     []string
	PlanID   *int64
	PlanSubs []string

	BlockKind   string
	BlockReason string
	Nick        string
	Balance     int64  // money on the balance, in cents
	RefCode     string // the code of the referral link
	ReferredBy  *int64 // the account that invited this one
	TgChat      *int64 // the Telegram chat linked to the account
	Channel     string // balancer channel of the VPN user
}

// User returns the VPN user of the account (for building links).
func (a *Account) User() User {
	return User{ID: a.UserID, Name: a.UserName, UUID: a.UUID, Enabled: a.Enabled, SubToken: a.SubToken, Expires: a.Expires, Subs: a.Subs, PlanID: a.PlanID, PlanSubs: a.PlanSubs, BlockKind: a.BlockKind, BlockReason: a.BlockReason, Nick: a.Nick, Channel: a.Channel}
}

const accountCols = `a.id, a.email, a.pass_hash, a.user_id, a.blocked, a.note, a.created, a.last_login, u.name, u.uuid::text, u.sub_token, u.expires_at, u.enabled, u.subs, u.plan_id, (SELECT p.subs FROM plans p WHERE p.id=u.plan_id), COALESCE(u.block_kind,''), u.block_reason, u.nick, a.balance_cents, COALESCE(a.ref_code,''), a.referred_by, a.tg_chat, u.channel`

func scanAccount(r pgx.Row) (*Account, error) {
	var a Account
	err := r.Scan(&a.ID, &a.Email, &a.PassHash, &a.UserID, &a.Blocked, &a.Note, &a.Created, &a.LastLogin, &a.UserName, &a.UUID, &a.SubToken, &a.Expires, &a.Enabled, &a.Subs, &a.PlanID, &a.PlanSubs, &a.BlockKind, &a.BlockReason, &a.Nick, &a.Balance, &a.RefCode, &a.ReferredBy, &a.TgChat, &a.Channel)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &a, err
}

// CreateAccount registers a person: a VPN user (named by the email) with trialDays of access (0 = none until a payment) and the account.
func (s *Store) CreateAccount(ctx context.Context, email, passHash string, trialDays int) (*Account, error) {
	return s.CreateAccountIn(ctx, email, passHash, trialDays, chanAdmin)
}

// CreateAccountIn is CreateAccount with the channel of the balancer the new user belongs to.
func (s *Store) CreateAccountIn(ctx context.Context, email, passHash string, trialDays int, channel string) (*Account, error) {
	if channel != chanUsers {
		channel = chanAdmin
	}
	if strings.Contains(email, "~") {
		return nil, errors.New("bad email")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var taken bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM accounts WHERE email=$1) OR EXISTS(SELECT 1 FROM users WHERE name=$1)`, email).Scan(&taken); err != nil {
		return nil, err
	}
	if taken {
		return nil, ErrEmailTaken
	}
	var uid int64
	if err := tx.QueryRow(ctx, `INSERT INTO users(name, expires_at, channel) VALUES($1, now() + make_interval(days => $2), $3) RETURNING id`, email, trialDays, channel).Scan(&uid); err != nil {
		return nil, err
	}
	var id int64
	if err := tx.QueryRow(ctx, `INSERT INTO accounts(email, pass_hash, user_id) VALUES($1,$2,$3) RETURNING id`, email, passHash, uid).Scan(&id); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		if strings.Contains(err.Error(), "23505") {
			return nil, ErrEmailTaken
		}
		return nil, err
	}
	return s.AccountByID(ctx, id)
}

func (s *Store) AccountByID(ctx context.Context, id int64) (*Account, error) {
	return scanAccount(s.pool.QueryRow(ctx, `SELECT `+accountCols+` FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.id=$1`, id))
}

func (s *Store) AccountByUserID(ctx context.Context, userID int64) (*Account, error) {
	return scanAccount(s.pool.QueryRow(ctx, `SELECT `+accountCols+` FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.user_id=$1`, userID))
}

func (s *Store) AccountByEmail(ctx context.Context, email string) (*Account, error) {
	return scanAccount(s.pool.QueryRow(ctx, `SELECT `+accountCols+` FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.email=$1`, email))
}

func (s *Store) ListAccounts(ctx context.Context) ([]*Account, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+accountCols+` FROM accounts a JOIN users u ON u.id=a.user_id ORDER BY a.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) TouchLogin(ctx context.Context, id int64) {
	_, _ = s.pool.Exec(ctx, `UPDATE accounts SET last_login=now() WHERE id=$1`, id)
}

func (s *Store) SetAccountPassword(ctx context.Context, id int64, hash string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE accounts SET pass_hash=$2 WHERE id=$1`, id, hash)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SetAccountBlocked blocks or unblocks the account: the key stops working at once and the sessions end.
func (s *Store) SetAccountBlocked(ctx context.Context, id int64, blocked bool) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var uid int64
	if err := tx.QueryRow(ctx, `UPDATE accounts SET blocked=$2 WHERE id=$1 RETURNING user_id`, id, blocked).Scan(&uid); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET enabled=$2 WHERE id=$1`, uid, !blocked); err != nil {
		return err
	}
	if blocked {
		if _, err := tx.Exec(ctx, `DELETE FROM web_sessions WHERE account_id=$1`, id); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) SetAccountNote(ctx context.Context, id int64, note string) error {
	_, err := s.pool.Exec(ctx, `UPDATE accounts SET note=$2 WHERE id=$1`, id, note)
	return err
}

// DeleteAccount removes the account together with its VPN user, the counters and the payments.
func (s *Store) DeleteAccount(ctx context.Context, id int64) error {
	a, err := s.AccountByID(ctx, id)
	if err != nil {
		return err
	}
	_, err = s.DeleteUser(ctx, a.UserName) // the account follows (ON DELETE CASCADE)
	return err
}

// ---- subscription period ----

// ExtendUser adds days to the period: from the end of the current one, or from now if it has already ended.
// A user without a limit stays without a limit.
func (s *Store) ExtendUser(ctx context.Context, userID int64, days int) error {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET expires_at = CASE WHEN expires_at IS NULL THEN NULL
		ELSE GREATEST(expires_at, now()) + make_interval(days => $2) END WHERE id=$1`, userID, days)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SetUserExpiry sets the end of the period (nil = no limit).
func (s *Store) SetUserExpiry(ctx context.Context, userID int64, until *time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET expires_at=$2 WHERE id=$1`, userID, until)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) UserIDByName(ctx context.Context, name string) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `SELECT id FROM users WHERE name=$1`, name).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

// ---- sessions of the site ----

func (s *Store) CreateSession(ctx context.Context, accountID int64, tokenHash string, ttl time.Duration, ip string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO web_sessions(token_hash, account_id, expires, ip) VALUES($1,$2, now() + make_interval(secs => $3), $4)`,
		tokenHash, accountID, ttl.Seconds(), ip)
	return err
}

// SessionAccount returns the owner of a live session (blocked accounts have no sessions).
func (s *Store) SessionAccount(ctx context.Context, tokenHash string) (*Account, error) {
	return scanAccount(s.pool.QueryRow(ctx, `SELECT `+accountCols+` FROM web_sessions w JOIN accounts a ON a.id=w.account_id JOIN users u ON u.id=a.user_id
		WHERE w.token_hash=$1 AND w.expires > now() AND NOT a.blocked`, tokenHash))
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) {
	_, _ = s.pool.Exec(ctx, `DELETE FROM web_sessions WHERE token_hash=$1`, tokenHash)
}

// DeleteOtherSessions ends every session of the account except one (after a password change).
func (s *Store) DeleteOtherSessions(ctx context.Context, accountID int64, keepHash string) {
	_, _ = s.pool.Exec(ctx, `DELETE FROM web_sessions WHERE account_id=$1 AND token_hash <> $2`, accountID, keepHash)
}

func (s *Store) PurgeSessions(ctx context.Context) {
	_, _ = s.pool.Exec(ctx, `DELETE FROM web_sessions WHERE expires < now()`)
}

// ---- plans ----

type Plan struct {
	ID         int64    `json:"id"`
	Name       string   `json:"name"`
	Days       int      `json:"days"`
	PriceCents int      `json:"price_cents"`
	Currency   string   `json:"currency"`
	Enabled    bool     `json:"enabled"`
	Sort       int      `json:"sort"`
	Subs       []string `json:"subs"` // subscriptions of the plan; null = the default list
}

func (s *Store) ListPlans(ctx context.Context, onlyEnabled bool) ([]Plan, error) {
	q := `SELECT id,name,days,price_cents,currency,enabled,sort,subs FROM plans`
	if onlyEnabled {
		q += ` WHERE enabled`
	}
	rows, err := s.pool.Query(ctx, q+` ORDER BY sort, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Plan{}
	for rows.Next() {
		var p Plan
		if err := rows.Scan(&p.ID, &p.Name, &p.Days, &p.PriceCents, &p.Currency, &p.Enabled, &p.Sort, &p.Subs); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) PlanByID(ctx context.Context, id int64) (*Plan, error) {
	var p Plan
	err := s.pool.QueryRow(ctx, `SELECT id,name,days,price_cents,currency,enabled,sort,subs FROM plans WHERE id=$1`, id).
		Scan(&p.ID, &p.Name, &p.Days, &p.PriceCents, &p.Currency, &p.Enabled, &p.Sort, &p.Subs)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &p, err
}

func (p *Plan) validate() error {
	p.Name = strings.TrimSpace(p.Name)
	p.Currency = strings.ToUpper(strings.TrimSpace(p.Currency))
	if p.Currency == "" {
		p.Currency = "RUB"
	}
	if p.Subs != nil {
		keys, err := cleanSubKeys(p.Subs)
		if err != nil {
			return err
		}
		p.Subs = keys
	}
	switch {
	case p.Name == "" || len([]rune(p.Name)) > 60:
		return errors.New("название тарифа: от 1 до 60 символов")
	case p.Days < 1 || p.Days > 3660:
		return errors.New("срок тарифа: от 1 до 3660 дней")
	case p.PriceCents < 0 || p.PriceCents > 100_000_000:
		return errors.New("цена: от 0 до 1 000 000")
	case len(p.Currency) < 2 || len(p.Currency) > 5:
		return errors.New("валюта: код из 2-5 букв (RUB, USD ...)")
	}
	return nil
}

// SavePlan inserts (ID 0) or updates a plan and returns its ID.
func (s *Store) SavePlan(ctx context.Context, p Plan) (int64, error) {
	if err := p.validate(); err != nil {
		return 0, err
	}
	if p.ID == 0 {
		err := s.pool.QueryRow(ctx, `INSERT INTO plans(name,days,price_cents,currency,enabled,sort,subs) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
			p.Name, p.Days, p.PriceCents, p.Currency, p.Enabled, p.Sort, p.Subs).Scan(&p.ID)
		return p.ID, err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE plans SET name=$2,days=$3,price_cents=$4,currency=$5,enabled=$6,sort=$7,subs=$8 WHERE id=$1`,
		p.ID, p.Name, p.Days, p.PriceCents, p.Currency, p.Enabled, p.Sort, p.Subs)
	if err == nil && tag.RowsAffected() == 0 {
		return 0, ErrNotFound
	}
	return p.ID, err
}

func (s *Store) DeletePlan(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM plans WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// seedPlans puts three sample plans on the very first start (the operator edits them; deleting all of them is respected).
func (s *Store) seedPlans(ctx context.Context) error {
	var done bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM settings WHERE key='plans_seeded') OR EXISTS(SELECT 1 FROM plans)`).Scan(&done); err != nil {
		return err
	}
	if done {
		return nil
	}
	for i, p := range []Plan{{Name: "1 месяц", Days: 30, PriceCents: 19900}, {Name: "3 месяца", Days: 90, PriceCents: 49900}, {Name: "12 месяцев", Days: 365, PriceCents: 159000}} {
		p.Currency, p.Enabled, p.Sort = "RUB", true, i
		if _, err := s.SavePlan(ctx, p); err != nil {
			return err
		}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO settings(key,value) VALUES('plans_seeded','true') ON CONFLICT DO NOTHING`)
	return err
}

// ---- payments ----

type Payment struct {
	ID          int64      `json:"id"`
	AccountID   int64      `json:"account_id"`
	Email       string     `json:"email"`
	PlanName    string     `json:"plan_name"`
	Days        int        `json:"days"`
	AmountCents int        `json:"amount_cents"`
	Currency    string     `json:"currency"`
	Status      string     `json:"status"`
	Provider    string     `json:"provider"`
	Created     time.Time  `json:"created"`
	PaidAt      *time.Time `json:"paid_at"`
	Kind        string     `json:"kind"` // plan (a subscription) or topup (money to the balance)
	PromoCode   string     `json:"promo_code,omitempty"`
}

const paymentCols = `p.id, p.account_id, a.email, p.plan_name, p.days, p.amount_cents, p.currency, p.status, p.provider, p.created, p.paid_at, p.kind, p.promo_code`

func scanPayments(rows pgx.Rows) ([]Payment, error) {
	defer rows.Close()
	out := []Payment{}
	for rows.Next() {
		var p Payment
		if err := rows.Scan(&p.ID, &p.AccountID, &p.Email, &p.PlanName, &p.Days, &p.AmountCents, &p.Currency, &p.Status, &p.Provider, &p.Created, &p.PaidAt, &p.Kind, &p.PromoCode); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CreatePayment records a pending payment for a plan (the plan is copied: later edits of the plan do not change it).
func (s *Store) CreatePayment(ctx context.Context, accountID int64, plan Plan, provider string) (*Payment, error) {
	return s.CreatePaymentPromo(ctx, accountID, plan, provider, "")
}

func (s *Store) PaymentByID(ctx context.Context, id int64) (*Payment, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+paymentCols+` FROM payments p JOIN accounts a ON a.id=p.account_id WHERE p.id=$1`, id)
	if err != nil {
		return nil, err
	}
	ps, err := scanPayments(rows)
	if err != nil {
		return nil, err
	}
	if len(ps) == 0 {
		return nil, ErrNotFound
	}
	return &ps[0], nil
}

// ListPayments returns the latest payments (status "" = all); accountID 0 = of everybody.
func (s *Store) ListPayments(ctx context.Context, status string, accountID int64, limit int) ([]Payment, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+paymentCols+` FROM payments p JOIN accounts a ON a.id=p.account_id
		WHERE ($1='' OR p.status=$1) AND ($2=0 OR p.account_id=$2) ORDER BY (p.status='pending') DESC, p.created DESC LIMIT $3`, status, accountID, limit)
	if err != nil {
		return nil, err
	}
	return scanPayments(rows)
}

// extendAccount adds days to the period of the account's user (a user without a period stays without), lifts the
// block "unpaid" and, when a plan is given, makes it the user's plan.
func extendAccount(ctx context.Context, tx pgx.Tx, accID int64, days int, planID *int64) error {
	if days > 0 {
		if _, err := tx.Exec(ctx, `UPDATE users SET expires_at = CASE WHEN expires_at IS NULL THEN NULL ELSE GREATEST(expires_at, now()) + make_interval(days => $2) END
			WHERE id = (SELECT user_id FROM accounts WHERE id=$1)`, accID, days); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET block_kind=NULL, block_reason='', blocked_at=NULL WHERE block_kind='unpaid' AND id = (SELECT user_id FROM accounts WHERE id=$1)`, accID); err != nil {
		return err
	}
	if planID != nil { // the subscriptions of the paid plan apply from now on (a deleted plan changes nothing)
		if _, err := tx.Exec(ctx, `UPDATE users SET plan_id=COALESCE((SELECT id FROM plans WHERE id=$2), plan_id)
			WHERE id = (SELECT user_id FROM accounts WHERE id=$1)`, accID, *planID); err != nil {
			return err
		}
	}
	return nil
}

// MarkPaid confirms a pending payment: a subscription extends the period of the account, a top-up goes to the balance.
// The first paid subscription of an invited person rewards the one who invited him. Safe to repeat: only the first call counts.
func (s *Store) MarkPaid(ctx context.Context, id int64) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var accID int64
	var days, amount int
	var planID *int64
	var kind string
	err = tx.QueryRow(ctx, `UPDATE payments SET status='paid', paid_at=now() WHERE id=$1 AND status='pending' RETURNING account_id, days, plan_id, kind, amount_cents`, id).Scan(&accID, &days, &planID, &kind, &amount)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if kind == "topup" {
		if err := addBalance(ctx, tx, accID, int64(amount), "topup", "пополнение", &id); err != nil {
			return false, err
		}
		return true, tx.Commit(ctx)
	}
	if err := extendAccount(ctx, tx, accID, days, planID); err != nil {
		return false, err
	}
	if err := s.rewardReferrer(ctx, tx, accID, amount); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func (s *Store) CancelPayment(ctx context.Context, id int64) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE payments SET status='canceled' WHERE id=$1 AND status='pending'`, id)
	return tag.RowsAffected() > 0, err
}

// ---- traffic of one user ----

type UserTraffic struct {
	AllUp, AllDown int64
	D30Up, D30Down int64
}

func (s *Store) UserTrafficOf(ctx context.Context, name string) (UserTraffic, error) {
	var t UserTraffic
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(SUM(up),0), COALESCE(SUM(down),0),
		COALESCE(SUM(up) FILTER (WHERE hour > now()-interval '30 days'),0), COALESCE(SUM(down) FILTER (WHERE hour > now()-interval '30 days'),0)
		FROM traffic_all WHERE user_name=$1`, name).Scan(&t.AllUp, &t.AllDown, &t.D30Up, &t.D30Down)
	return t, err
}

// UserUsage is the traffic of a user over all servers: this one and those that report to it (traffic_all, see servers.go).
func (s *Store) UserUsage(ctx context.Context, name string) (UserTraffic, error) {
	return s.UserTrafficOf(ctx, name)
}

// ---- certificate cache (golang.org/x/crypto/acme/autocert.Cache) ----

func (s *Store) AcmeGet(ctx context.Context, key string) ([]byte, error) {
	var b []byte
	err := s.pool.QueryRow(ctx, `SELECT data FROM acme_cache WHERE key=$1`, key).Scan(&b)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return b, err
}

func (s *Store) AcmePut(ctx context.Context, key string, data []byte) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO acme_cache(key,data) VALUES($1,$2) ON CONFLICT (key) DO UPDATE SET data=EXCLUDED.data, updated=now()`, key, data)
	return err
}

func (s *Store) AcmeDelete(ctx context.Context, key string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM acme_cache WHERE key=$1`, key)
	return err
}

// BulkPlanSubs changes the subscription list of every plan at once: "set" gives all of them exactly keys, "add" and "remove"
// change the lists they have (a plan without its own list starts from base, the default list). With resetUsers the personal lists
// of users are dropped, so everybody follows the plan (or the default) again.
func (s *Store) BulkPlanSubs(ctx context.Context, mode string, keys, base []string, resetUsers bool) (plans int, users int64, err error) {
	if mode != "set" && mode != "add" && mode != "remove" {
		return 0, 0, fmt.Errorf("режим: set, add или remove")
	}
	ps, err := s.ListPlans(ctx, false)
	if err != nil {
		return 0, 0, err
	}
	for _, p := range ps {
		cur := p.Subs
		if cur == nil {
			cur = base
		}
		var next []string
		switch mode {
		case "set":
			next = append(next, keys...)
		case "add":
			next = append(next, cur...)
			for _, k := range keys {
				if !hasSub(next, k) {
					next = append(next, k)
				}
			}
		case "remove":
			for _, k := range cur {
				if !hasSub(keys, k) {
					next = append(next, k)
				}
			}
		}
		if next == nil {
			next = []string{}
		}
		p.Subs = next
		if _, err := s.SavePlan(ctx, p); err != nil {
			return plans, 0, err
		}
		plans++
	}
	if resetUsers {
		tag, err := s.pool.Exec(ctx, `UPDATE users SET subs=NULL WHERE subs IS NOT NULL`)
		if err != nil {
			return plans, 0, err
		}
		users = tag.RowsAffected()
	}
	return plans, users, nil
}
