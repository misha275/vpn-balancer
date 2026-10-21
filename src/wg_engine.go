package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The WireGuard endpoint of the gateway: one sing-box process of its own that is not part of the blue/green ring,
// so that a new configuration for the users does not drop the tunnel (see wireguard.go).

type wgProc struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	exited   chan struct{}
	stopping bool
	cfg      []byte
	fp       string
}

type wgReq struct {
	Config json.RawMessage `json:"config"` // empty = switch off
	FP     string          `json:"fp"`
}

func (e *Engine) wgPath() string     { return filepath.Join(e.workDir, "wg.json") }
func (e *Engine) wgLastPath() string { return filepath.Join(e.workDir, "wg-last.json") }

// ApplyWG starts, restarts or stops the WireGuard sing-box. The same config again is a no-op.
func (e *Engine) ApplyWG(ctx context.Context, cfg []byte, fp string) error {
	w := &e.wg
	w.mu.Lock()
	same := w.cmd != nil && w.fp == fp && string(w.cfg) == string(cfg)
	w.mu.Unlock()
	if same {
		return nil
	}
	if len(cfg) == 0 {
		e.stopWG()
		w.mu.Lock()
		w.cfg, w.fp = nil, fp
		w.mu.Unlock()
		e.persistWG(nil, fp)
		return nil
	}
	if err := os.MkdirAll(e.workDir, 0o755); err != nil {
		return err
	}
	tmp := e.wgPath() + ".new"
	if err := os.WriteFile(tmp, cfg, 0o600); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(cctx, e.bin, "check", "-c", tmp).CombinedOutput(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("sing-box check failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	e.stopWG() // the UDP port is free again only after the old process is gone
	if err := os.Rename(tmp, e.wgPath()); err != nil {
		return err
	}
	if err := e.startWG(cfg, fp); err != nil {
		return err
	}
	e.persistWG(cfg, fp)
	return nil
}

func (e *Engine) startWG(cfg []byte, fp string) error {
	w := &e.wg
	cmd := exec.Command(e.bin, "run", "-c", e.wgPath())
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return err
	}
	pw.Close()
	go func() {
		defer pr.Close()
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			l := reANSI.ReplaceAllString(sc.Text(), "")
			fmt.Fprintln(os.Stdout, "[wireguard] "+l)
			e.logs.Add("[wireguard] " + l)
		}
		_, _ = io.Copy(io.Discard, pr)
	}()
	exited := make(chan struct{})
	w.mu.Lock()
	w.cmd, w.exited, w.stopping, w.cfg, w.fp = cmd, exited, false, cfg, fp
	w.mu.Unlock()
	go func() {
		err := cmd.Wait()
		close(exited)
		w.mu.Lock()
		intended := w.stopping || w.cmd != cmd
		w.mu.Unlock()
		if intended || e.stopped.Load() {
			return
		}
		log.Printf("gateway: the WireGuard sing-box exited (%v), restarting", err)
		for !e.stopped.Load() {
			time.Sleep(2 * time.Second)
			w.mu.Lock()
			still := w.cmd == cmd && !w.stopping
			w.mu.Unlock()
			if !still {
				return
			}
			if err := e.startWG(cfg, fp); err != nil {
				log.Printf("gateway: WireGuard restart failed: %v", err)
				continue
			}
			return
		}
	}()
	// ready when the process stays up for a moment (the UDP port itself cannot be probed)
	select {
	case <-exited:
		return errors.New("the WireGuard sing-box exited right after the start (is the UDP port busy?)")
	case <-time.After(700 * time.Millisecond):
	}
	return nil
}

func (e *Engine) stopWG() {
	w := &e.wg
	w.mu.Lock()
	cmd, exited := w.cmd, w.exited
	w.stopping = true
	w.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		<-exited
	}
	w.mu.Lock()
	if w.cmd == cmd {
		w.cmd = nil
	}
	w.mu.Unlock()
}

func (e *Engine) persistWG(cfg []byte, fp string) {
	b, err := json.Marshal(wgReq{Config: cfg, FP: fp})
	if err != nil {
		return
	}
	tmp := e.wgLastPath() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, e.wgLastPath())
	}
}

// recoverWG restores the tunnel after a restart of the gateway without waiting for the controller.
func (e *Engine) recoverWG() {
	b, err := os.ReadFile(e.wgLastPath())
	if err != nil {
		return
	}
	var r wgReq
	if json.Unmarshal(b, &r) != nil || len(r.Config) == 0 {
		return
	}
	log.Printf("gateway: restoring the WireGuard tunnel")
	if err := e.ApplyWG(context.Background(), r.Config, r.FP); err != nil {
		log.Printf("gateway: WireGuard restore failed: %v", err)
	}
}

func (e *Engine) wgState() (running bool, fp string) {
	e.wg.mu.Lock()
	defer e.wg.mu.Unlock()
	return e.wg.cmd != nil, e.wg.fp
}

// serveWGFront hands the flows of the WireGuard sing-box to the active instance (wg-in inbound).
func (e *Engine) serveWGFront(ctx context.Context) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", e.wgFront))
	if err != nil {
		log.Printf("gateway: WireGuard front cannot listen on 127.0.0.1:%d: %v", e.wgFront, err)
		return
	}
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go e.handleTo(c, func(s *engSlot) int { return s.wgIn }, true)
	}
}

// ---------------------------------------------------------------- client side

func (g *remoteGateway) ApplyWG(ctx context.Context, cfg []byte, fp string) error {
	_, err := g.do(ctx, "POST", "/v1/wg", wgReq{Config: cfg, FP: fp}, 40*time.Second)
	return err
}

func (e *Engine) registerWG(mux *http.ServeMux, auth func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("POST /v1/wg", auth(func(w http.ResponseWriter, r *http.Request) {
		var req wgReq
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			apiErr(w, 400, fmt.Errorf("bad request"))
			return
		}
		if err := e.ApplyWG(context.Background(), req.Config, req.FP); err != nil {
			apiErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]string{"ok": "applied"})
	}))
}
