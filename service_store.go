package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// The service around the balancer: the balance of an account, the referral program, promo codes. Payments themselves are
// a placeholder (see PaymentProvider in site.go); everything here works the same when a real provider is plugged in.

// RefReward is what the referral program gives. It is read when a rewarded payment happens, so a change of the settings
// applies at once.
type RefReward struct {
	Days        int // days for the one who invited
	Percent     int // percent of the payment of the invited one that goes to the balance of the one who invited
	InviteeDays int // days for the invited one for his first payment
}

// rewardSource returns the current reward settings (the site sets it to read the config).
var rewardSource = func() RefReward { return RefReward{Days: 7} }

var (
	ErrNoPromo        = errors.New("такого промокода нет или он больше не действует")
	ErrPromoUsed      = errors.New("вы уже использовали этот промокод")
	ErrPromoKind      = errors.New("этот промокод даёт скидку: введите его при оплате тарифа")
	ErrNotDiscount    = errors.New("этот промокод вводится в кабинете, а не при оплате")
	ErrNoMoney        = errors.New("на балансе не хватает денег")
	reRefCode         = regexp.MustCompile(`^[A-Za-z0-9]{4,16}$`)
	rePromoCode       = regexp.MustCompile(`^[A-Za-z0-9_-]{3,32}$`)
	refAlphabet       = "abcdefghjkmnpqrstuvwxyz23456789"
	maxTopupCents     = 100000000
	errBalanceBadSign = errors.New("баланс не может стать отрицательным")
)

func randCode(n int, alphabet string) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// addBalance changes the balance inside a transaction and writes the operation; a balance never goes below zero.
func addBalance(ctx context.Context, tx pgx.Tx, accID, delta int64, kind, note string, paymentID *int64) error {
	t, err := tx.Exec(ctx, `UPDATE accounts SET balance_cents=balance_cents+$2 WHERE id=$1 AND balance_cents+$2>=0`, accID, delta)
	if err != nil {
		return err
	}
	if t.RowsAffected() == 0 {
		return errBalanceBadSign
	}
	_, err = tx.Exec(ctx, `INSERT INTO balance_ops(account_id,delta_cents,kind,note,payment_id) VALUES($1,$2,$3,$4,$5)`, accID, delta, kind, note, paymentID)
	return err
}

// AdjustBalance is the operation of the administrator (a correction, a gift, a refund). delta is in cents.
func (s *Store) AdjustBalance(ctx context.Context, accID, delta int64, kind, note string) error {
	if delta == 0 || delta > int64(maxTopupCents) || delta < -int64(maxTopupCents) {
		return errors.New("сумма: от -1 000 000 до 1 000 000, не ноль")
	}
	if len([]rune(note)) > 200 {
		return errors.New("пояснение до 200 символов")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := addBalance(ctx, tx, accID, delta, kind, note, nil); err != nil {
		if errors.Is(err, errBalanceBadSign) {
			return err
		}
		return err
	}
	return tx.Commit(ctx)
}

// BalanceOp is a line of the history of the balance.
type BalanceOp struct {
	ID      int64     `json:"id"`
	Delta   int64     `json:"delta_cents"`
	Kind    string    `json:"kind"`
	Note    string    `json:"note"`
	Created time.Time `json:"created"`
}

func (s *Store) BalanceOps(ctx context.Context, accID int64, limit int) ([]BalanceOp, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,delta_cents,kind,note,created FROM balance_ops WHERE account_id=$1 ORDER BY id DESC LIMIT $2`, accID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BalanceOp{}
	for rows.Next() {
		var o BalanceOp
		if err := rows.Scan(&o.ID, &o.Delta, &o.Kind, &o.Note, &o.Created); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ---- referrals ----

// EnsureRefCode gives the account the code of its referral link (once).
func (s *Store) EnsureRefCode(ctx context.Context, accID int64) (string, error) {
	var code string
	if err := s.pool.QueryRow(ctx, `SELECT COALESCE(ref_code,'') FROM accounts WHERE id=$1`, accID).Scan(&code); err != nil {
		return "", err
	}
	if code != "" {
		return code, nil
	}
	for i := 0; i < 8; i++ {
		c := randCode(8, refAlphabet)
		t, err := s.pool.Exec(ctx, `UPDATE accounts SET ref_code=$2 WHERE id=$1 AND ref_code IS NULL`, accID, c)
		if err != nil {
			if strings.Contains(err.Error(), "23505") { // the code is taken: try another
				continue
			}
			return "", err
		}
		if t.RowsAffected() > 0 {
			return c, nil
		}
		return s.EnsureRefCode(ctx, accID) // somebody else gave it meanwhile
	}
	return "", errors.New("не удалось выдать код")
}

// AttachReferral remembers who invited an account (only once, never oneself). An unknown code is ignored.
func (s *Store) AttachReferral(ctx context.Context, accID int64, code string) bool {
	code = strings.TrimSpace(code)
	if !reRefCode.MatchString(code) {
		return false
	}
	t, err := s.pool.Exec(ctx, `UPDATE accounts SET referred_by=(SELECT id FROM accounts WHERE lower(ref_code)=lower($2))
		WHERE id=$1 AND referred_by IS NULL AND EXISTS (SELECT 1 FROM accounts r WHERE lower(r.ref_code)=lower($2) AND r.id<>$1)`, accID, code)
	return err == nil && t.RowsAffected() > 0
}

// RefStats are the numbers of the referral program of an account.
type RefStats struct {
	Invited     int   // registered by his link
	Paid        int   // of them paid for a subscription
	BonusDays   int   // days he earned
	BonusCents  int64 // money he earned
	InviteeDays int
}

func (s *Store) RefStatsOf(ctx context.Context, accID int64) (RefStats, error) {
	var r RefStats
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE ref_rewarded) FROM accounts WHERE referred_by=$1`, accID).Scan(&r.Invited, &r.Paid)
	if err != nil {
		return r, err
	}
	_ = s.pool.QueryRow(ctx, `SELECT COALESCE(SUM(delta_cents) FILTER (WHERE kind='referral'),0), COALESCE(SUM(CASE WHEN kind='referral_days' THEN NULLIF(regexp_replace(note,'\D','','g'),'')::int ELSE 0 END),0)
		FROM balance_ops WHERE account_id=$1`, accID).Scan(&r.BonusCents, &r.BonusDays)
	return r, nil
}

// rewardReferrer pays the reward for the first paid subscription of an invited account.
func (s *Store) rewardReferrer(ctx context.Context, tx pgx.Tx, accID int64, amountCents int) error {
	var ref *int64
	var done bool
	if err := tx.QueryRow(ctx, `SELECT CASE WHEN EXISTS (SELECT 1 FROM accounts r WHERE r.id=a.referred_by) THEN a.referred_by END, a.ref_rewarded FROM accounts a WHERE a.id=$1 FOR UPDATE`, accID).Scan(&ref, &done); err != nil {
		return err
	}
	if ref == nil || done {
		return nil
	}
	if _, err := tx.Exec(ctx, `UPDATE accounts SET ref_rewarded=true WHERE id=$1`, accID); err != nil {
		return err
	}
	rw := rewardSource()
	if rw.Days > 0 {
		if err := extendAccount(ctx, tx, *ref, rw.Days, nil); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO balance_ops(account_id,delta_cents,kind,note) VALUES($1,0,'referral_days',$2)`, *ref, fmt.Sprintf("+%d дн. за приглашённого", rw.Days)); err != nil {
			return err
		}
	}
	if rw.Percent > 0 && amountCents > 0 {
		if bonus := int64(amountCents) * int64(rw.Percent) / 100; bonus > 0 {
			if err := addBalance(ctx, tx, *ref, bonus, "referral", fmt.Sprintf("%d%% от оплаты приглашённого", rw.Percent), nil); err != nil {
				return err
			}
		}
	}
	if rw.InviteeDays > 0 {
		if err := extendAccount(ctx, tx, accID, rw.InviteeDays, nil); err != nil {
			return err
		}
	}
	return nil
}

// ---- promo codes ----

type Promo struct {
	Code    string     `json:"code"`
	Kind    string     `json:"kind"` // percent | days | balance
	Value   int        `json:"value"`
	MaxUses int        `json:"max_uses"`
	Used    int        `json:"used"`
	Expires *time.Time `json:"expires"`
	Enabled bool       `json:"enabled"`
	Note    string     `json:"note"`
}

func (p Promo) validate() error {
	if !rePromoCode.MatchString(p.Code) {
		return errors.New("код: 3-32 символа, латиница, цифры, - и _")
	}
	switch p.Kind {
	case "percent":
		if p.Value < 1 || p.Value > 100 {
			return errors.New("скидка: от 1 до 100 процентов")
		}
	case "days":
		if p.Value < 1 || p.Value > 3650 {
			return errors.New("дни: от 1 до 3650")
		}
	case "balance":
		if p.Value < 1 || p.Value > maxTopupCents {
			return errors.New("сумма на баланс: положительная, в копейках/центах")
		}
	default:
		return errors.New("вид промокода: percent, days или balance")
	}
	if p.MaxUses < 0 || p.MaxUses > 1000000 || len(p.Note) > 200 {
		return errors.New("лимит использований 0-1 000 000, заметка до 200 символов")
	}
	return nil
}

// SavePromo creates a promo code or changes the existing one (the counter of uses stays).
func (s *Store) SavePromo(ctx context.Context, p Promo) error {
	p.Code = strings.ToUpper(strings.TrimSpace(p.Code))
	if err := p.validate(); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO promos(code,kind,value,max_uses,expires,enabled,note) VALUES($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (code) DO UPDATE SET kind=EXCLUDED.kind, value=EXCLUDED.value, max_uses=EXCLUDED.max_uses, expires=EXCLUDED.expires, enabled=EXCLUDED.enabled, note=EXCLUDED.note`,
		p.Code, p.Kind, p.Value, p.MaxUses, p.Expires, p.Enabled, p.Note)
	return err
}

func (s *Store) DeletePromo(ctx context.Context, code string) (bool, error) {
	t, err := s.pool.Exec(ctx, `DELETE FROM promos WHERE code=$1`, strings.ToUpper(code))
	return t.RowsAffected() > 0, err
}

func (s *Store) ListPromos(ctx context.Context) ([]Promo, error) {
	rows, err := s.pool.Query(ctx, `SELECT code,kind,value,max_uses,used,expires,enabled,note FROM promos ORDER BY created DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Promo{}
	for rows.Next() {
		var p Promo
		if err := rows.Scan(&p.Code, &p.Kind, &p.Value, &p.MaxUses, &p.Used, &p.Expires, &p.Enabled, &p.Note); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// takePromo checks a promo code for an account and counts the use (inside the transaction), or says why it does not work.
func takePromo(ctx context.Context, tx pgx.Tx, accID int64, code string) (*Promo, error) {
	code = strings.ToUpper(strings.TrimSpace(code))
	var p Promo
	err := tx.QueryRow(ctx, `SELECT code,kind,value,max_uses,used,expires,enabled,note FROM promos WHERE code=$1 FOR UPDATE`, code).
		Scan(&p.Code, &p.Kind, &p.Value, &p.MaxUses, &p.Used, &p.Expires, &p.Enabled, &p.Note)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoPromo
	}
	if err != nil {
		return nil, err
	}
	if !p.Enabled || (p.Expires != nil && p.Expires.Before(time.Now())) || (p.MaxUses > 0 && p.Used >= p.MaxUses) {
		return nil, ErrNoPromo
	}
	t, err := tx.Exec(ctx, `INSERT INTO promo_uses(code,account_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, code, accID)
	if err != nil {
		return nil, err
	}
	if t.RowsAffected() == 0 {
		return nil, ErrPromoUsed
	}
	if _, err := tx.Exec(ctx, `UPDATE promos SET used=used+1 WHERE code=$1`, code); err != nil {
		return nil, err
	}
	return &p, nil
}

// RedeemPromo applies a promo code of the kind "days" or "balance" at once. A discount code is entered at the payment.
func (s *Store) RedeemPromo(ctx context.Context, accID int64, code string) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	code = strings.ToUpper(strings.TrimSpace(code))
	var kind string
	if err := tx.QueryRow(ctx, `SELECT kind FROM promos WHERE code=$1`, code).Scan(&kind); err != nil {
		return "", ErrNoPromo
	}
	if kind == "percent" {
		return "", ErrPromoKind
	}
	p, err := takePromo(ctx, tx, accID, code)
	if err != nil {
		return "", err
	}
	var msg string
	switch p.Kind {
	case "days":
		if err := extendAccount(ctx, tx, accID, p.Value, nil); err != nil {
			return "", err
		}
		msg = fmt.Sprintf("Промокод применён: +%d %s доступа", p.Value, daysWord(p.Value))
	case "balance":
		if err := addBalance(ctx, tx, accID, int64(p.Value), "promo", "промокод "+p.Code, nil); err != nil {
			return "", err
		}
		msg = "Промокод применён: деньги на балансе"
	}
	return msg, tx.Commit(ctx)
}

// CreatePaymentPromo is CreatePayment with a discount code (percent); the code is used up when the payment is created.
func (s *Store) CreatePaymentPromo(ctx context.Context, accountID int64, plan Plan, provider, promo string) (*Payment, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	amount, code := plan.PriceCents, ""
	if strings.TrimSpace(promo) != "" {
		var kind string
		if err := tx.QueryRow(ctx, `SELECT kind FROM promos WHERE code=$1`, strings.ToUpper(strings.TrimSpace(promo))).Scan(&kind); err != nil {
			return nil, ErrNoPromo
		}
		if kind != "percent" {
			return nil, ErrNotDiscount
		}
		p, err := takePromo(ctx, tx, accountID, promo)
		if err != nil {
			return nil, err
		}
		amount, code = plan.PriceCents-plan.PriceCents*p.Value/100, p.Code
	}
	var id int64
	if err := tx.QueryRow(ctx, `INSERT INTO payments(account_id, plan_name, days, amount_cents, currency, provider, plan_id, promo_code) VALUES($1,$2,$3,$4,$5,$6,NULLIF($7::bigint,0),$8) RETURNING id`,
		accountID, plan.Name, plan.Days, amount, plan.Currency, provider, plan.ID, code).Scan(&id); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.PaymentByID(ctx, id)
}

// CreateTopup records a pending top-up of the balance.
func (s *Store) CreateTopup(ctx context.Context, accountID int64, cents int, currency, provider string) (*Payment, error) {
	if cents < 100 || cents > maxTopupCents {
		return nil, errors.New("сумма пополнения: от 1 до 1 000 000")
	}
	var id int64
	if err := s.pool.QueryRow(ctx, `INSERT INTO payments(account_id, plan_name, days, amount_cents, currency, provider, kind) VALUES($1,'Пополнение баланса',0,$2,$3,$4,'topup') RETURNING id`,
		accountID, cents, currency, provider).Scan(&id); err != nil {
		return nil, err
	}
	return s.PaymentByID(ctx, id)
}

// PayFromBalance buys a plan with the money of the balance (with an optional discount code): the payment is made and
// confirmed at once. The balance is debited in the same transaction as the payment is created.
func (s *Store) PayFromBalance(ctx context.Context, accID int64, plan Plan, promo string) (*Payment, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	amount, code := plan.PriceCents, ""
	if strings.TrimSpace(promo) != "" {
		p, err := takePromo(ctx, tx, accID, promo)
		if err != nil {
			return nil, err
		}
		if p.Kind != "percent" {
			return nil, ErrPromoKind
		}
		amount, code = plan.PriceCents-plan.PriceCents*p.Value/100, p.Code
	}
	var id int64
	if err := tx.QueryRow(ctx, `INSERT INTO payments(account_id, plan_name, days, amount_cents, currency, provider, plan_id, promo_code) VALUES($1,$2,$3,$4,$5,'balance',NULLIF($6::bigint,0),$7) RETURNING id`,
		accID, plan.Name, plan.Days, amount, plan.Currency, plan.ID, code).Scan(&id); err != nil {
		return nil, err
	}
	if amount > 0 {
		if err := addBalance(ctx, tx, accID, -int64(amount), "purchase", "тариф «"+plan.Name+"»", &id); err != nil {
			if errors.Is(err, errBalanceBadSign) {
				return nil, ErrNoMoney
			}
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	if _, err := s.MarkPaid(ctx, id); err != nil { // cannot fail for a pending payment; if it does, the money goes back
		_ = s.AdjustBalance(ctx, accID, int64(amount), "refund", "оплата не прошла")
		return nil, err
	}
	return s.PaymentByID(ctx, id)
}

// SetPaymentExt remembers the identifier of the payment at the provider.
func (s *Store) SetPaymentExt(ctx context.Context, id int64, ext string) {
	if len(ext) > 120 {
		ext = ext[:120]
	}
	_, _ = s.pool.Exec(ctx, `UPDATE payments SET ext_id=$2 WHERE id=$1`, id, ext)
}

// AccountByRefCode finds the account of a referral link.
func (s *Store) AccountByRefCode(ctx context.Context, code string) (*Account, error) {
	return scanAccount(s.pool.QueryRow(ctx, `SELECT `+accountCols+` FROM accounts a JOIN users u ON u.id=a.user_id WHERE lower(a.ref_code)=lower($1)`, code))
}

// ---- telegram link codes ----

// NewTgLinkCode makes a one-time code that links the account with a Telegram chat (valid 15 minutes).
func (s *Store) NewTgLinkCode(ctx context.Context, accID int64) (string, error) {
	_, _ = s.pool.Exec(ctx, `DELETE FROM tg_links WHERE created < now() - interval '15 minutes' OR account_id=$1`, accID)
	code := randCode(8, refAlphabet)
	_, err := s.pool.Exec(ctx, `INSERT INTO tg_links(code,account_id) VALUES($1,$2)`, code, accID)
	return code, err
}

// LinkTelegram binds a chat to the account of a link code. A chat is linked to one account only.
func (s *Store) LinkTelegram(ctx context.Context, code string, chat int64) (*Account, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var accID int64
	err = tx.QueryRow(ctx, `DELETE FROM tg_links WHERE code=$1 AND created > now() - interval '15 minutes' RETURNING account_id`, strings.ToLower(strings.TrimSpace(code))).Scan(&accID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE accounts SET tg_chat=NULL WHERE tg_chat=$1`, chat); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE accounts SET tg_chat=$2 WHERE id=$1`, accID, chat); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.AccountByID(ctx, accID)
}

func (s *Store) UnlinkTelegram(ctx context.Context, accID int64) error {
	_, err := s.pool.Exec(ctx, `UPDATE accounts SET tg_chat=NULL WHERE id=$1`, accID)
	return err
}

func (s *Store) AccountByTgChat(ctx context.Context, chat int64) (*Account, error) {
	return scanAccount(s.pool.QueryRow(ctx, `SELECT `+accountCols+` FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.tg_chat=$1`, chat))
}
