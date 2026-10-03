package main

import (
	"context"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

// Collector samples the machine and the gateway, keeps the history for the charts in memory
// (and in the database, so that it survives a restart) and writes the traffic of every user to the database.
type Collector struct {
	st   *Store
	core *Core
	logs *LogRing // console of the controller

	interval time.Duration

	mu      sync.RWMutex
	hist    []SysSample
	last    SysSample
	static  sysStatic
	gw      GWStats
	gwAt    time.Time
	gwErr   string
	speed   map[string]UserDelta // bytes per second now (Conns unused)
	active  map[string]time.Time
	pending map[string]UserDelta
	seen    map[string]SeenInfo

	prevCPU cpuTimes
	prevOK  bool
	prevTot struct {
		epoch    int64
		up, down int64
		at       time.Time
		ok       bool
	}
}

func NewCollector(st *Store, core *Core, logs *LogRing) *Collector {
	return &Collector{st: st, core: core, logs: logs, interval: 5 * time.Second,
		speed: map[string]UserDelta{}, active: map[string]time.Time{}, pending: map[string]UserDelta{}, seen: map[string]SeenInfo{}}
}

func (c *Collector) Run(ctx context.Context) {
	if c.st != nil {
		lc, cancel := context.WithTimeout(ctx, 10*time.Second)
		if old, err := c.st.LoadMetrics(lc, time.Now().Add(-24*time.Hour)); err == nil {
			c.mu.Lock()
			c.hist = old
			c.mu.Unlock()
		}
		cancel()
	}
	tk := time.NewTicker(c.interval)
	defer tk.Stop()
	n := 0
	for {
		select {
		case <-ctx.Done():
			c.flush(context.Background())
			return
		case <-tk.C:
			n++
			c.Sample(ctx, n%2 == 0)
			if n%6 == 0 {
				c.flush(ctx)
				c.persistMetric(ctx)
			}
		}
	}
}

// Sample takes one measurement. keep = also add it to the history.
func (c *Collector) Sample(ctx context.Context, keep bool) {
	now := time.Now()
	s := SysSample{T: now.Unix()}
	if t, ok := readCPUTimes(); ok {
		if c.prevOK {
			s.CPU = cpuPercent(c.prevCPU, t)
		}
		c.prevCPU, c.prevOK = t, true
	}
	s.MemUsed, s.MemTotal = readMem()
	s.Mem = pct(s.MemUsed, s.MemTotal)
	s.DiskUsed, s.DiskTotal = readDisk("/")
	s.Disk = pct(s.DiskUsed, s.DiskTotal)
	s.Load1 = readLoad1()

	gctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	gs, err := c.core.GatewayStats(gctx)
	cancel()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.static = readSysStatic()
	if err != nil {
		c.gwErr = err.Error()
		c.prevTot.ok = false
		c.speed = map[string]UserDelta{}
	} else {
		c.gwErr = ""
		dt := now.Sub(c.prevTot.at).Seconds()
		if c.prevTot.ok && c.prevTot.epoch == gs.Epoch && dt > 0.5 {
			s.Up = float64(gs.UpTotal-c.prevTot.up) / dt
			s.Down = float64(gs.DownTotal-c.prevTot.down) / dt
			if s.Up < 0 {
				s.Up = 0
			}
			if s.Down < 0 {
				s.Down = 0
			}
		}
		speed := map[string]UserDelta{}
		if dt > 0.5 {
			for name, d := range gs.Deltas {
				speed[name] = UserDelta{Up: int64(float64(d.Up) / dt), Down: int64(float64(d.Down) / dt)}
			}
		}
		c.speed = speed
		for name, d := range gs.Deltas {
			p := c.pending[name]
			p.Up, p.Down, p.Conns = p.Up+d.Up, p.Down+d.Down, p.Conns+d.Conns
			c.pending[name] = p
			if d.Up+d.Down > 0 {
				c.active[name] = now
			}
		}
		online := map[string]bool{}
		for _, se := range gs.Sessions {
			if se.User == "" {
				continue
			}
			online[se.User] = true
			if !strings.HasPrefix(se.User, "~") {
				c.seen[se.User] = SeenInfo{At: now, IP: se.IP}
			}
		}
		for name, d := range gs.Deltas {
			if _, ok := c.seen[name]; !ok && !strings.HasPrefix(name, "~") && d.Conns+d.Up+d.Down > 0 {
				c.seen[name] = SeenInfo{At: now}
			}
		}
		s.Conns, s.Users = gs.Conns, len(online)
		c.gw, c.gwAt = gs, now
		c.prevTot.epoch, c.prevTot.up, c.prevTot.down, c.prevTot.at, c.prevTot.ok = gs.Epoch, gs.UpTotal, gs.DownTotal, now, true
	}
	c.last = s
	if keep {
		c.hist = append(c.hist, s)
		cut := now.Add(-24 * time.Hour).Unix()
		i := 0
		for i < len(c.hist) && c.hist[i].T < cut {
			i++
		}
		if i > 0 {
			c.hist = append([]SysSample(nil), c.hist[i:]...)
		}
	}
}

func (c *Collector) flush(ctx context.Context) {
	if c.st == nil {
		return
	}
	c.mu.Lock()
	pend, seen := c.pending, c.seen
	c.pending, c.seen = map[string]UserDelta{}, map[string]SeenInfo{}
	c.mu.Unlock()
	fc, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := c.st.AddTraffic(fc, time.Now(), pend); err != nil {
		log.Printf("stats: saving traffic failed (will retry): %v", err)
		c.mu.Lock() // put it back
		for k, d := range pend {
			p := c.pending[k]
			p.Up, p.Down, p.Conns = p.Up+d.Up, p.Down+d.Down, p.Conns+d.Conns
			c.pending[k] = p
		}
		c.mu.Unlock()
	}
	if err := c.st.TouchSeen(fc, seen); err != nil {
		log.Printf("stats: saving last activity failed: %v", err)
	}
}

func (c *Collector) persistMetric(ctx context.Context) {
	if c.st == nil {
		return
	}
	c.mu.RLock()
	m := c.last
	c.mu.RUnlock()
	if m.T == 0 {
		return
	}
	pc, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.st.InsertMetric(pc, m); err != nil {
		log.Printf("stats: saving history failed: %v", err)
	}
}

// History returns up to ~300 points for the charts.
func (c *Collector) History(ctx context.Context, rng string) ([]SysSample, error) {
	span := map[string]time.Duration{"1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour}[rng]
	if span == 0 {
		span = time.Hour
	}
	since := time.Now().Add(-span)
	var src []SysSample
	if span > 24*time.Hour && c.st != nil {
		var err error
		if src, err = c.st.LoadMetrics(ctx, since); err != nil {
			return nil, err
		}
	} else {
		c.mu.RLock()
		for _, p := range c.hist {
			if p.T >= since.Unix() {
				src = append(src, p)
			}
		}
		c.mu.RUnlock()
	}
	return downsample(src, 300), nil
}

func downsample(src []SysSample, max int) []SysSample {
	if len(src) <= max {
		return src
	}
	out := make([]SysSample, 0, max)
	step := float64(len(src)) / float64(max)
	for i := 0; i < max; i++ {
		a, b := int(float64(i)*step), int(float64(i+1)*step)
		if b > len(src) {
			b = len(src)
		}
		if a >= b {
			continue
		}
		var m SysSample
		for _, p := range src[a:b] {
			m.CPU += p.CPU
			m.Mem += p.Mem
			m.Disk += p.Disk
			m.Load1 += p.Load1
			m.Up += p.Up
			m.Down += p.Down
			m.Conns += p.Conns
			m.Users += p.Users
		}
		n := float64(b - a)
		m.CPU, m.Mem, m.Disk, m.Load1, m.Up, m.Down = m.CPU/n, m.Mem/n, m.Disk/n, m.Load1/n, m.Up/n, m.Down/n
		m.Conns, m.Users = m.Conns/(b-a), m.Users/(b-a)
		m.T = src[b-1].T
		last := src[b-1]
		m.MemUsed, m.MemTotal, m.DiskUsed, m.DiskTotal = last.MemUsed, last.MemTotal, last.DiskUsed, last.DiskTotal
		out = append(out, m)
	}
	return out
}

// ---------------------------------------------------------------- view for the panel and the command line

type UserStat struct {
	Name     string   `json:"name"`
	Label    string   `json:"label,omitempty"`
	Enabled  bool     `json:"enabled"`
	Removed  bool     `json:"removed,omitempty"`
	Online   bool     `json:"online"`
	Active   bool     `json:"active"` // data moved in the last seconds
	Conns    int      `json:"conns"`
	IPs      []string `json:"ips"`
	UpBps    int64    `json:"up_bps"`
	DownBps  int64    `json:"down_bps"`
	H24Up    int64    `json:"h24_up"`
	H24Down  int64    `json:"h24_down"`
	D7Up     int64    `json:"d7_up"`
	D7Down   int64    `json:"d7_down"`
	D30Up    int64    `json:"d30_up"`
	D30Down  int64    `json:"d30_down"`
	AllUp    int64    `json:"all_up"`
	AllDown  int64    `json:"all_down"`
	AllConns int64    `json:"all_conns"`
	LastSeen *int64   `json:"last_seen,omitempty"` // unix seconds
	LastIP   string   `json:"last_ip,omitempty"`
	Errors   int64    `json:"errors"`             // errors and blocked destinations since the gateway started
	LastErr  *int64   `json:"last_err,omitempty"` // unix seconds
	ErrMsg   string   `json:"err_msg,omitempty"`
}

type StatsView struct {
	Sys       SysSample     `json:"sys"`
	Static    sysStatic     `json:"static"`
	GwError   string        `json:"gateway_error,omitempty"`
	GwEpoch   int64         `json:"gateway_epoch"`
	Users     []UserStat    `json:"users"`
	Other     []UserStat    `json:"other"`
	Sessions  []SessInfo    `json:"sessions"`
	Invalid   []InvalidInfo `json:"invalid"`
	UpTotal   int64         `json:"up_total"`
	DownTotal int64         `json:"down_total"`
}

func (c *Collector) View(ctx context.Context) (*StatsView, error) {
	var sums map[string]*TrafficSum
	var users []User
	if c.st != nil {
		var err error
		if sums, err = c.st.TrafficSummary(ctx); err != nil {
			return nil, err
		}
		if users, err = c.st.ListUsers(ctx); err != nil {
			return nil, err
		}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := time.Now()
	v := &StatsView{Sys: c.last, Static: c.static, GwError: c.gwErr, GwEpoch: c.gw.Epoch, UpTotal: c.gw.UpTotal, DownTotal: c.gw.DownTotal,
		Sessions: c.gw.Sessions, Invalid: c.gw.Invalid}
	if v.Sessions == nil {
		v.Sessions = []SessInfo{}
	}
	if v.Invalid == nil {
		v.Invalid = []InvalidInfo{}
	}
	live := map[string]*UserStat{}
	row := func(name string) *UserStat {
		u := live[name]
		if u == nil {
			u = &UserStat{Name: name, IPs: []string{}}
			live[name] = u
		}
		return u
	}
	for _, se := range c.gw.Sessions {
		if se.User == "" {
			continue
		}
		u := row(se.User)
		u.Online, u.Conns = true, u.Conns+1
		dup := false
		for _, ip := range u.IPs {
			dup = dup || ip == se.IP
		}
		if !dup {
			u.IPs = append(u.IPs, se.IP)
		}
	}
	names := map[string]bool{}
	for _, u := range users {
		row(u.Name).Enabled = u.Enabled
		names[u.Name] = true
	}
	for n := range sums {
		row(n)
	}
	for n := range c.pending {
		row(n)
	}
	for n := range c.gw.Errs {
		row(n)
	}
	for n := range live {
		u := live[n]
		if s := sums[n]; s != nil {
			u.H24Up, u.H24Down, u.D7Up, u.D7Down, u.D30Up, u.D30Down = s.H24Up, s.H24Down, s.D7Up, s.D7Down, s.D30Up, s.D30Down
			u.AllUp, u.AllDown, u.AllConns, u.LastIP = s.AllUp, s.AllDown, s.AllConns, s.LastIP
			if !s.LastSeen.IsZero() {
				t := s.LastSeen.Unix()
				u.LastSeen = &t
			}
		}
		if p, ok := c.pending[n]; ok { // not yet written to the database
			u.H24Up, u.H24Down, u.D7Up, u.D7Down, u.D30Up, u.D30Down = u.H24Up+p.Up, u.H24Down+p.Down, u.D7Up+p.Up, u.D7Down+p.Down, u.D30Up+p.Up, u.D30Down+p.Down
			u.AllUp, u.AllDown, u.AllConns = u.AllUp+p.Up, u.AllDown+p.Down, u.AllConns+p.Conns
		}
		if e, ok := c.gw.Errs[n]; ok {
			u.Errors, u.ErrMsg = e.Count, e.Msg
			t := e.Last
			u.LastErr = &t
		}
		if sp, ok := c.speed[n]; ok {
			u.UpBps, u.DownBps = sp.Up, sp.Down
		}
		if t, ok := c.active[n]; ok && now.Sub(t) < 12*time.Second {
			u.Active = true
		}
		if sn, ok := c.seen[n]; ok { // fresher than the database
			t := sn.At.Unix()
			u.LastSeen = &t
			if sn.IP != "" {
				u.LastIP = sn.IP
			}
		}
		if u.Online {
			t := now.Unix()
			u.LastSeen = &t
		}
		switch {
		case n == userInvalid:
			u.Label = "не прошли проверку Reality"
			v.Other = append(v.Other, *u)
		case n == userUnknown:
			u.Label = "оборвались до определения пользователя"
			v.Other = append(v.Other, *u)
		default:
			if !names[n] {
				u.Removed = true
			}
			v.Users = append(v.Users, *u)
		}
	}
	sort.Slice(v.Users, func(i, j int) bool {
		a, b := v.Users[i], v.Users[j]
		if a.Online != b.Online {
			return a.Online
		}
		if a.D7Up+a.D7Down != b.D7Up+b.D7Down {
			return a.D7Up+a.D7Down > b.D7Up+b.D7Down
		}
		return a.Name < b.Name
	})
	sort.Slice(v.Other, func(i, j int) bool { return v.Other[i].Name < v.Other[j].Name })
	if v.Users == nil {
		v.Users = []UserStat{}
	}
	if v.Other == nil {
		v.Other = []UserStat{}
	}
	return v, nil
}
