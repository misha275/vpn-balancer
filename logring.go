package main

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

// LogRing keeps the last lines of a log in memory for the panel console.
type LogRing struct {
	mu    sync.Mutex
	epoch int64
	seq   int64
	buf   []LogLine
	cap   int
	part  string // an unfinished last line
}

type LogLine struct {
	Seq  int64  `json:"seq"`
	T    int64  `json:"t"` // unix ms
	Text string `json:"text"`
}

type LogPage struct {
	Epoch int64     `json:"epoch"` // changes when the process restarted (sequence numbers start again)
	Last  int64     `json:"last"`
	Lines []LogLine `json:"lines"`
}

func NewLogRing(capacity int) *LogRing {
	return &LogRing{epoch: time.Now().UnixNano(), cap: capacity}
}

var reANSI = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// Write implements io.Writer so the ring can be a log output.
func (r *LogRing) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	text := r.part + string(p)
	r.part = ""
	parts := strings.Split(text, "\n")
	r.part = parts[len(parts)-1]
	for _, ln := range parts[:len(parts)-1] {
		r.add(ln)
	}
	if len(r.part) > 8192 { // a line without end: do not grow forever
		r.add(r.part)
		r.part = ""
	}
	return len(p), nil
}

// Add stores one line.
func (r *LogRing) Add(line string) {
	r.mu.Lock()
	r.add(line)
	r.mu.Unlock()
}

func (r *LogRing) add(line string) {
	line = strings.TrimRight(reANSI.ReplaceAllString(line, ""), "\r")
	if line == "" {
		return
	}
	if len(line) > 2000 {
		line = line[:2000] + "…"
	}
	r.seq++
	r.buf = append(r.buf, LogLine{Seq: r.seq, T: time.Now().UnixMilli(), Text: line})
	if len(r.buf) > r.cap+r.cap/4 {
		r.buf = append([]LogLine(nil), r.buf[len(r.buf)-r.cap:]...)
	}
}

// Since returns lines with Seq > after (at most limit, the newest ones).
func (r *LogRing) Since(after int64, limit int) LogPage {
	r.mu.Lock()
	defer r.mu.Unlock()
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	pg := LogPage{Epoch: r.epoch, Last: r.seq}
	if after > r.seq {
		after = 0
	}
	start := len(r.buf)
	for start > 0 && r.buf[start-1].Seq > after {
		start--
	}
	if len(r.buf)-start > limit {
		start = len(r.buf) - limit
	}
	pg.Lines = append([]LogLine(nil), r.buf[start:]...)
	return pg
}
