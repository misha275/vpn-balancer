package main

import (
	"log"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Traffic accounting inside the gateway.
//
// The front sees every client connection and counts the bytes exactly. It cannot
// see which user a connection belongs to (that is inside the Reality/VLESS layer),
// but sing-box writes "[name] inbound connection to ..." into its log, and the
// connection id of that line ties the user to the loopback port the front used to
// reach the instance. So the front and the log together give "user X moved N bytes".
// Only counters are kept: nothing about the sites the users open is stored or shown.

const (
	userInvalid = "~invalid" // connections that did not pass the Reality check (scanners, wrong keys, wrong fingerprint ...)
	userUnknown = "~unknown" // connections that ended before a user could be determined
)

type UserDelta struct {
	Up    int64 `json:"up"`    // bytes sent by the client (upload)
	Down  int64 `json:"down"`  // bytes sent to the client (download)
	Conns int64 `json:"conns"` // connections
}

type SessInfo struct {
	ID    uint64    `json:"id"`
	User  string    `json:"user"` // "" while not yet known
	IP    string    `json:"ip"`
	Since time.Time `json:"since"`
	Up    int64     `json:"up"`
	Down  int64     `json:"down"`
	Idle  int       `json:"idle_sec"` // seconds since the last byte
}

type InvalidInfo struct {
	IP    string    `json:"ip"`
	Count int64     `json:"count"`
	Last  time.Time `json:"last"`
}

// GWStats is what the gateway reports to the controller. Deltas are drained: every call returns what happened since the previous one.
type GWStats struct {
	Epoch     int64                `json:"epoch"` // start time of the gateway process, a change means "counters restarted"
	Now       time.Time            `json:"now"`
	UpTotal   int64                `json:"up_total"`
	DownTotal int64                `json:"down_total"`
	Conns     int                  `json:"conns"`
	Sessions  []SessInfo           `json:"sessions"`
	Deltas    map[string]UserDelta `json:"deltas"`
	Invalid   []InvalidInfo        `json:"invalid"`
	Errs      map[string]UserErr   `json:"errs,omitempty"`
}

// UserErr summarises what went wrong for one user since the gateway started.
type UserErr struct {
	Count int64  `json:"n"`
	Last  int64  `json:"t"` // unix seconds
	Msg   string `json:"m"`
}

type sessKey struct{ slot, port int }

type session struct {
	id             uint64
	key            sessKey
	ip             string
	start          time.Time
	up, down       atomic.Int64
	last           atomic.Int64 // unix nano
	user           string       // guarded by tracker.mu
	invalid        bool
	closed         bool
	counted        bool
	repUp, repDown int64
}

type tracker struct {
	mu      sync.Mutex
	live    map[sessKey]*session
	deltas  map[string]UserDelta
	invalid map[string]*InvalidInfo
	recent  map[string]int64 // invalid connections per ip since the last summary line
	next    uint64
	epoch   int64
	errs    map[string]UserErr
	ulogs   map[string]*LogRing // errors and blocked connections of every user, for the diagnostic console

	upTotal, downTotal atomic.Int64
	settle             time.Duration // how long a closed connection waits for its user line
}

func newTracker() *tracker {
	return &tracker{live: map[sessKey]*session{}, deltas: map[string]UserDelta{}, invalid: map[string]*InvalidInfo{},
		recent: map[string]int64{}, errs: map[string]UserErr{}, ulogs: map[string]*LogRing{}, epoch: time.Now().Unix(), settle: 1500 * time.Millisecond}
}

func (t *tracker) open(slot, port int, client net.Addr) *session {
	ip := ""
	if client != nil {
		ip = client.String()
		if h, _, err := net.SplitHostPort(ip); err == nil {
			ip = h
		}
	}
	s := &session{key: sessKey{slot, port}, ip: ip, start: time.Now()}
	s.last.Store(s.start.UnixNano())
	t.mu.Lock()
	t.next++
	s.id = t.next
	t.live[s.key] = s
	t.mu.Unlock()
	return s
}

// end is called when the client connection is finished.
func (t *tracker) end(s *session) {
	t.mu.Lock()
	s.closed = true
	t.mu.Unlock()
	time.AfterFunc(t.settle, func() { t.finalize(s) })
}

func (t *tracker) finalize(s *session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.account(s, true)
	if t.live[s.key] == s {
		delete(t.live, s.key)
	}
}

// account moves not yet reported bytes of a session into the deltas. Must hold t.mu.
func (t *tracker) account(s *session, final bool) {
	name := s.user
	switch {
	case s.invalid:
		name = userInvalid
	case name == "" && final:
		name = userUnknown
	case name == "":
		return // wait for the user line
	}
	up, down := s.up.Load(), s.down.Load()
	d := t.deltas[name]
	d.Up += up - s.repUp
	d.Down += down - s.repDown
	if !s.counted {
		d.Conns++
		s.counted = true
	}
	s.repUp, s.repDown = up, down
	t.deltas[name] = d
}

func (t *tracker) setUser(slot, port int, name string) {
	t.mu.Lock()
	if s := t.live[sessKey{slot, port}]; s != nil {
		s.user = name
	}
	t.mu.Unlock()
}

func (t *tracker) markInvalid(slot, port int) {
	t.mu.Lock()
	if s := t.live[sessKey{slot, port}]; s != nil && !s.invalid {
		s.invalid = true
		ip := s.ip
		inf := t.invalid[ip]
		if inf == nil {
			if len(t.invalid) >= 200 {
				t.invalid = map[string]*InvalidInfo{}
			}
			inf = &InvalidInfo{IP: ip}
			t.invalid[ip] = inf
		}
		inf.Count++
		inf.Last = time.Now()
		t.recent[ip]++
	}
	t.mu.Unlock()
}

// userEvent records a problem of one user (an error of the connection, a blocked destination).
func (t *tracker) userEvent(name, text string) {
	t.mu.Lock()
	r := t.ulogs[name]
	if r == nil {
		if len(t.ulogs) >= 500 {
			t.mu.Unlock()
			return
		}
		r = NewLogRing(300)
		t.ulogs[name] = r
	}
	e := t.errs[name]
	e.Count++
	e.Last = time.Now().Unix()
	e.Msg = text
	if len(e.Msg) > 200 {
		e.Msg = e.Msg[:200] + "…"
	}
	t.errs[name] = e
	t.mu.Unlock()
	r.Add(text)
}

// UserLogs returns the diagnostic console of one user.
func (t *tracker) UserLogs(name string, after int64, limit int) LogPage {
	t.mu.Lock()
	r := t.ulogs[name]
	t.mu.Unlock()
	if r == nil {
		return LogPage{Epoch: t.epoch, Lines: []LogLine{}}
	}
	pg := r.Since(after, limit)
	pg.Epoch = t.epoch
	return pg
}

// drain returns the live picture and everything counted since the previous call.
func (t *tracker) drain() GWStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	st := GWStats{Epoch: t.epoch, Now: now, UpTotal: t.upTotal.Load(), DownTotal: t.downTotal.Load()}
	for _, s := range t.live {
		t.account(s, false)
		if s.closed {
			continue
		}
		st.Conns++
		if len(st.Sessions) < 1000 {
			st.Sessions = append(st.Sessions, SessInfo{ID: s.id, User: s.user, IP: s.ip, Since: s.start,
				Up: s.up.Load(), Down: s.down.Load(), Idle: int(now.Sub(time.Unix(0, s.last.Load())).Seconds())})
		}
	}
	sort.Slice(st.Sessions, func(i, j int) bool { return st.Sessions[i].ID < st.Sessions[j].ID })
	st.Deltas, t.deltas = t.deltas, map[string]UserDelta{}
	if len(t.errs) > 0 {
		st.Errs = make(map[string]UserErr, len(t.errs))
		for k, v := range t.errs {
			st.Errs[k] = v
		}
	}
	for _, v := range t.invalid {
		st.Invalid = append(st.Invalid, *v)
	}
	sort.Slice(st.Invalid, func(i, j int) bool { return st.Invalid[i].Last.After(st.Invalid[j].Last) })
	return st
}

// reportLoop writes one summary line instead of one line per rejected connection.
func (t *tracker) reportLoop(stop <-chan struct{}) {
	tk := time.NewTicker(30 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tk.C:
			t.mu.Lock()
			rec := t.recent
			t.recent = map[string]int64{}
			t.mu.Unlock()
			if len(rec) == 0 {
				continue
			}
			var total int64
			type kv struct {
				ip string
				n  int64
			}
			var l []kv
			for ip, n := range rec {
				total += n
				l = append(l, kv{ip, n})
			}
			sort.Slice(l, func(i, j int) bool { return l[i].n > l[j].n })
			var parts []string
			for i, e := range l {
				if i == 5 {
					parts = append(parts, "…")
					break
				}
				parts = append(parts, e.ip+" ×"+itoa(e.n))
			}
			log.Printf("gateway: %d connections in 30 s did not pass the Reality check (%s). Usually a client with wrong keys/short id/fingerprint, or a scanner", total, strings.Join(parts, ", "))
		}
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// ---------------------------------------------------------------- counting connection

// cconn counts the bytes of a client connection (reads = upload, writes = download).
type cconn struct {
	net.Conn
	s *session
	t *tracker
}

func (c *cconn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.s.up.Add(int64(n))
		c.t.upTotal.Add(int64(n))
		c.s.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func (c *cconn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.s.down.Add(int64(n))
		c.t.downTotal.Add(int64(n))
		c.s.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func (c *cconn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// ---------------------------------------------------------------- sing-box log lines

var (
	reFrom  = regexp.MustCompile(`\[(\d+) [^\]]*\] inbound/vless\[vless-in\]: inbound connection from 127\.0\.0\.1:(\d+)`)
	reUser  = regexp.MustCompile(`\[(\d+) [^\]]*\] inbound/vless\[vless-in\]: \[([^\]]+)\] inbound connection to `)
	reBad   = regexp.MustCompile(`inbound/vless\[vless-in\]: process connection from 127\.0\.0\.1:(\d+): .*REALITY: processed invalid connection`)
	reLevel = regexp.MustCompile(`^(?:\S+ \S+ \S+ )?(TRACE|DEBUG|INFO)\b`)
)

// lineSink handles the output of one sing-box instance.
type lineSink struct {
	slot   int
	t      *tracker
	idPort map[string]int
	idUser map[string]string // connection id -> user, to attach later errors of the same connection
	pass   func(line string) // lines worth showing to the operator
}

func (l *lineSink) line(s string) {
	s = reANSI.ReplaceAllString(s, "")
	if m := reFrom.FindStringSubmatch(s); m != nil {
		if len(l.idPort) > 20000 {
			l.idPort = map[string]int{}
		}
		l.idPort[m[1]] = atoiSafe(m[2])
		return
	}
	if m := reUser.FindStringSubmatch(s); m != nil {
		if len(l.idUser) > 20000 || l.idUser == nil {
			l.idUser = map[string]string{}
		}
		l.idUser[m[1]] = m[2]
		if p, ok := l.idPort[m[1]]; ok {
			l.t.setUser(l.slot, p, m[2])
			delete(l.idPort, m[1])
		}
		return
	}
	if m := reBad.FindStringSubmatch(s); m != nil {
		l.t.markInvalid(l.slot, atoiSafe(m[1]))
		return // summarised by reportLoop
	}
	user := ""
	if m := reConnID.FindStringSubmatch(s); m != nil {
		user = l.idUser[m[1]]
	}
	if strings.Contains(s, "outbound/block[") {
		if user != "" { // a rule of the balancer blocked a destination of this user: worth knowing when "site X does not open"
			l.t.userEvent(user, stampLine(s, "заблокировано правилами"))
		}
		return
	}
	if reLevel.MatchString(s) {
		return // ordinary connection chatter, not kept (it names the sites users open)
	}
	if user != "" {
		l.t.userEvent(user, stampLine(s, ""))
	}
	if l.pass != nil {
		l.pass(s)
	}
}

var reConnID = regexp.MustCompile(`\[(\d+) [^\]]*\]`)

// stampLine trims sing-box's own timestamp prefix (the console adds its own) and appends an optional note.
func stampLine(s, note string) string {
	s = strings.TrimSpace(s)
	if f := strings.Fields(s); len(f) > 3 && strings.HasPrefix(f[0], "+") {
		s = strings.Join(f[3:], " ")
	}
	if note != "" {
		s = note + ": " + s
	}
	return s
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}
