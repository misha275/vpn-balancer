package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// SBProc runs one sing-box process (end node, WireGuard node) from a config that can be replaced: the process is
// restarted only when the config really changed, and started again if it dies.
type SBProc struct {
	Bin  string
	Dir  string
	Name string

	mu     sync.Mutex
	cmd    *exec.Cmd
	exited chan struct{}
	hash   [32]byte
	have   bool
	ctx    context.Context
	failed int
}

func NewSBProc(ctx context.Context, bin, dir, name string) *SBProc {
	return &SBProc{Bin: bin, Dir: dir, Name: name, ctx: ctx}
}

// CheckConfig runs `sing-box check` on a config.
func CheckConfig(bin string, cfg []byte) error {
	f, err := os.CreateTemp("", "sbcheck-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	f.Write(cfg)
	f.Close()
	out, err := exec.Command(bin, "check", "-c", f.Name()).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("sing-box check: %s", msg)
	}
	return nil
}

// Apply installs a config. Returns whether the process was (re)started. An invalid config is refused and the
// running one stays.
func (p *SBProc) Apply(cfg []byte) (bool, error) {
	if err := CheckConfig(p.Bin, cfg); err != nil {
		return false, err
	}
	h := sha256.Sum256(cfg)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.have && h == p.hash && p.cmd != nil {
		return false, nil
	}
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return false, err
	}
	if err := os.WriteFile(filepath.Join(p.Dir, p.Name+".json"), cfg, 0o600); err != nil {
		return false, err
	}
	p.stopLocked()
	p.hash, p.have = h, true
	return true, p.startLocked()
}

func (p *SBProc) startLocked() error {
	cmd := exec.Command(p.Bin, "run", "-c", filepath.Join(p.Dir, p.Name+".json"), "-D", p.Dir)
	cmd.Stdout, cmd.Stderr = &logWriter{prefix: "sing-box: "}, &logWriter{prefix: "sing-box: "}
	if err := cmd.Start(); err != nil {
		p.cmd = nil
		return err
	}
	p.cmd = cmd
	exited := make(chan struct{})
	p.exited = exited
	go func() {
		err := cmd.Wait()
		close(exited)
		p.mu.Lock()
		cur := p.cmd == cmd
		if cur {
			p.cmd = nil
		}
		p.mu.Unlock()
		if !cur || p.ctx.Err() != nil {
			return
		}
		log.Printf("sing-box (%s) stopped: %v; starting again", p.Name, err)
		time.Sleep(3 * time.Second)
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.cmd == nil && p.ctx.Err() == nil && p.have {
			if err := p.startLocked(); err != nil {
				log.Printf("sing-box (%s): %v", p.Name, err)
			}
		}
	}()
	return nil
}

func (p *SBProc) stopLocked() {
	cmd := p.cmd
	if cmd == nil || cmd.Process == nil {
		return
	}
	p.cmd = nil // the watcher sees that this stop is intended
	cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.exited:
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		<-p.exited
	}
}

// Running reports whether the process is alive.
func (p *SBProc) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cmd != nil
}

func (p *SBProc) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.have = false
	p.stopLocked()
}

type logWriter struct{ prefix string }

func (w *logWriter) Write(b []byte) (int, error) {
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if l != "" {
			log.Print(w.prefix + l)
		}
	}
	return len(b), nil
}
