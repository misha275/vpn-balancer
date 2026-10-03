package main

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// SysSample is one measurement of the machine. In a container /proc/stat, /proc/meminfo and /proc/uptime
// describe the whole host, and the root file system reports the disk of the host.
type SysSample struct {
	T         int64   `json:"t"` // unix seconds
	CPU       float64 `json:"cpu"`
	Mem       float64 `json:"mem"`
	Disk      float64 `json:"disk"`
	Load1     float64 `json:"load1"`
	Up        float64 `json:"up"`   // bytes/s from clients to the gateway
	Down      float64 `json:"down"` // bytes/s from the gateway to clients
	Conns     int     `json:"conns"`
	Users     int     `json:"users"` // users online now
	MemUsed   uint64  `json:"mem_used"`
	MemTotal  uint64  `json:"mem_total"`
	DiskUsed  uint64  `json:"disk_used"`
	DiskTotal uint64  `json:"disk_total"`
}

type cpuTimes struct{ total, idle uint64 }

func readCPUTimes() (cpuTimes, bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuTimes{}, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return cpuTimes{}, false
	}
	return parseCPULine(sc.Text())
}

func parseCPULine(line string) (cpuTimes, bool) {
	fs := strings.Fields(line)
	if len(fs) < 5 || fs[0] != "cpu" {
		return cpuTimes{}, false
	}
	var t cpuTimes
	for i, v := range fs[1:] {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return cpuTimes{}, false
		}
		if i < 8 { // user nice system idle iowait irq softirq steal (guest is already in user)
			t.total += n
		}
		if i == 3 || i == 4 {
			t.idle += n
		}
	}
	return t, true
}

func cpuPercent(a, b cpuTimes) float64 {
	dt := float64(b.total - a.total)
	if dt <= 0 || b.total < a.total {
		return 0
	}
	p := 100 * (1 - float64(b.idle-a.idle)/dt)
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}

func parseMeminfo(data string) (total, avail uint64) {
	for _, ln := range strings.Split(data, "\n") {
		fs := strings.Fields(ln)
		if len(fs) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(fs[1], 10, 64)
		switch fs[0] {
		case "MemTotal:":
			total = v * 1024
		case "MemAvailable:":
			avail = v * 1024
		}
	}
	return
}

func readMem() (used, total uint64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	total, avail := parseMeminfo(string(b))
	if avail > total {
		avail = total
	}
	return total - avail, total
}

func readDisk(path string) (used, total uint64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0
	}
	bs := uint64(st.Bsize)
	free := uint64(st.Bfree) * bs
	total = uint64(st.Blocks) * bs
	avail := uint64(st.Bavail) * bs
	used = total - free
	// like df: the share is used / (used + what a normal user can still use)
	total = used + avail
	return
}

func readLoad1() float64 {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	fs := strings.Fields(string(b))
	if len(fs) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(fs[0], 64)
	return v
}

func readUptime() float64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fs := strings.Fields(string(b))
	if len(fs) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(fs[0], 64)
	return v
}

func pct(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(used) / float64(total)
}

// sysStatic is what does not change between samples.
type sysStatic struct {
	CPUs   int     `json:"cpus"`
	Uptime float64 `json:"uptime_sec"`
	OS     string  `json:"os"`
}

func readSysStatic() sysStatic {
	return sysStatic{CPUs: runtime.NumCPU(), Uptime: readUptime(), OS: runtime.GOOS + "/" + runtime.GOARCH}
}
