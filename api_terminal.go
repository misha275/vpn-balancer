package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// The terminal of the panel runs the very commands of the command line (see cliHelp): the line is split like in a shell
// (spaces, "double" and 'single' quotes) and handed to runCLI, whose output is collected.
var termMu sync.Mutex

// splitArgs splits a line into words; quotes keep spaces in a word, a backslash escapes the next character.
func splitArgs(line string) ([]string, error) {
	var out []string
	var cur strings.Builder
	var quote rune
	have := false
	esc := false
	for _, r := range line {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\' && quote != '\'':
			esc = true
			have = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote, have = r, true
		case r == ' ' || r == '\t':
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteRune(r)
			have = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("не закрыта кавычка")
	}
	if have {
		out = append(out, cur.String())
	}
	return out, nil
}

const termMaxOut = 200 << 10

// runCaptured runs a command and returns what it printed. Commands print to the standard output, so only one runs at a time.
func runCaptured(ctx context.Context, cfg *Config, st *Store, cmd string, args []string) (string, error) {
	termMu.Lock()
	defer termMu.Unlock()
	rd, wr, err := os.Pipe()
	if err != nil {
		return "", err
	}
	old := os.Stdout
	os.Stdout = wr
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&limitBuf{b: &buf, max: termMaxOut}, rd)
		close(done)
	}()
	ok, runErr := runCLI(ctx, cfg, st, cmd, args)
	os.Stdout = old
	wr.Close()
	<-done
	rd.Close()
	if !ok && runErr == nil {
		runErr = fmt.Errorf("неизвестная команда %q (help — список команд)", cmd)
	}
	return buf.String(), runErr
}

type limitBuf struct {
	b   *bytes.Buffer
	max int
}

func (l *limitBuf) Write(p []byte) (int, error) {
	if l.b.Len() < l.max {
		room := l.max - l.b.Len()
		if len(p) > room {
			l.b.Write(p[:room])
			l.b.WriteString("\n… вывод обрезан")
		} else {
			l.b.Write(p)
		}
	}
	return len(p), nil
}

// terminal: POST {"line":"users"} -> {"out":"…","error":"…"}.
func (a *API) terminal(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Line string `json:"line"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in); err != nil {
		apiErr(w, 400, fmt.Errorf("ожидается JSON {\"line\": \"команда\"}"))
		return
	}
	args, err := splitArgs(strings.TrimSpace(in.Line))
	if err != nil {
		writeJSON(w, 200, map[string]string{"out": "", "error": err.Error()})
		return
	}
	if len(args) == 0 {
		writeJSON(w, 200, map[string]string{"out": "", "error": ""})
		return
	}
	if args[0] == "run" || args[0] == "token" {
		writeJSON(w, 200, map[string]string{"out": "", "error": "эта команда доступна только в командной строке сервера"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	out, runErr := runCaptured(ctx, a.cfg, a.store, args[0], args[1:])
	res := map[string]string{"out": out, "error": ""}
	if runErr != nil {
		res["error"] = runErr.Error()
	}
	writeJSON(w, 200, res)
}

// terminalHelp: the reference of commands and settings for the panel.
func (a *API) terminalHelp(w http.ResponseWriter, r *http.Request) {
	type setting struct {
		Key  string `json:"key"`
		Help string `json:"help"`
	}
	var sets []setting
	for _, d := range settingDefs {
		sets = append(sets, setting{d.key, d.help})
	}
	writeJSON(w, 200, map[string]any{"groups": parseCLIHelp(), "settings": sets})
}
