package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// HelpCmd is one command of the reference (as the terminal of the panel shows it).
type HelpCmd struct {
	Cmd  string `json:"cmd"`
	Desc string `json:"desc"`
}

// HelpGroup is a section of the reference.
type HelpGroup struct {
	Title string    `json:"title"`
	Cmds  []HelpCmd `json:"cmds"`
}

var reHelpLine = regexp.MustCompile(`^  (\S.*?)\s{2,}(\S.*)$`)

// parseCLIHelp turns the text of cliHelp into groups of commands.
func parseCLIHelp() []HelpGroup {
	var out []HelpGroup
	var cur *HelpGroup
	for _, line := range strings.Split(cliHelp, "\n") {
		switch {
		case strings.TrimSpace(line) == "":
		case !strings.HasPrefix(line, " "):
			if strings.HasPrefix(line, "Команды (") || strings.HasPrefix(line, "Ключи настроек") {
				continue
			}
			out = append(out, HelpGroup{Title: strings.TrimSpace(line)})
			cur = &out[len(out)-1]
		case cur == nil:
		default:
			if m := reHelpLine.FindStringSubmatch(line); m != nil && !strings.HasPrefix(line, "   ") {
				cur.Cmds = append(cur.Cmds, HelpCmd{Cmd: strings.TrimSpace(m[1]), Desc: strings.TrimSpace(m[2])})
			} else if t := strings.TrimSpace(line); !strings.HasPrefix(line, "   ") {
				cur.Cmds = append(cur.Cmds, HelpCmd{Cmd: t}) // the description is on the next line
			} else if n := len(cur.Cmds); n > 0 {
				cur.Cmds[n-1].Desc = strings.TrimSpace(cur.Cmds[n-1].Desc + " " + strings.TrimSpace(line))
			}
		}
	}
	return out
}

// cliHelpTopic prints the help of one command or of one setting.
func cliHelpTopic(topic string) error {
	if topic == "settings" || topic == "ключи" {
		keys := settingKeys()
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("%-26s %s\n", k, settingDefFor(k).help)
		}
		return nil
	}
	if d := settingDefFor(topic); d != nil {
		fmt.Printf("%s\n  %s\n  значение: get %s, изменить: set %s ЗНАЧЕНИЕ, вернуть из config.yaml: reset %s\n", topic, d.help, topic, topic, topic)
		return nil
	}
	found := false
	for _, g := range parseCLIHelp() {
		for _, c := range g.Cmds {
			f := strings.Fields(c.Cmd)
			if len(f) == 0 {
				continue
			}
			match := false
			for _, alt := range strings.Split(f[0], "|") {
				match = match || alt == topic
			}
			if match {
				fmt.Printf("  %s\n      %s\n", c.Cmd, c.Desc)
				found = true
			}
		}
	}
	if !found {
		return fmt.Errorf("нет такой команды или настройки: %q (help — все команды, help settings — все настройки)", topic)
	}
	return nil
}
