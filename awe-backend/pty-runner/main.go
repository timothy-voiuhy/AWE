// Linux PTY supervisor. Runs as the tool container's main process, independent
// of backend and browser connections. No network port is exposed.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type control struct {
	Type string `json:"type"`
	Data string `json:"data"`
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

func ioctl(fd uintptr, op uintptr, ptr unsafe.Pointer) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, op, uintptr(ptr))
	if e != 0 {
		return e
	}
	return nil
}
func main() {
	if len(os.Args) < 2 {
		panic("serve or control required")
	}
	if os.Args[1] == "control" {
		c, e := net.Dial("unix", "/tmp/awe-pty.sock")
		if e != nil {
			panic(e)
		}
		defer c.Close()
		fmt.Fprintln(c, os.Args[2])
		io.Copy(os.Stdout, c)
		return
	}
	if err := serve(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func serve() error {
	master, e := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0600)
	if e != nil {
		return e
	}
	defer master.Close()
	var unlock int32
	if e = ioctl(master.Fd(), 0x40045431, unsafe.Pointer(&unlock)); e != nil {
		return e
	}
	var number uint32
	if e = ioctl(master.Fd(), 0x80045430, unsafe.Pointer(&number)); e != nil {
		return e
	}
	slave, e := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0600)
	if e != nil {
		return e
	}
	size := [4]uint16{32, 120, 0, 0}
	ioctl(master.Fd(), 0x5414, unsafe.Pointer(&size))
	cmd := exec.Command(os.Args[2], os.Args[3:]...)
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if e = cmd.Start(); e != nil {
		return e
	}
	slave.Close()
	listener, e := net.Listen("unix", "/tmp/awe-pty.sock")
	if e != nil {
		return e
	}
	defer listener.Close()
	os.Chmod("/tmp/awe-pty.sock", 0600)
	log, e := os.OpenFile("/output/.awe-terminal.jsonl", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if e != nil {
		return e
	}
	defer log.Close()
	var mu sync.Mutex
	last := time.Now()
	stopped := make(chan struct{})
	var seq int64
	var written int64
	limit, _ := strconv.ParseInt(os.Getenv("AWE_TRANSCRIPT_MAX_BYTES"), 10, 64)
	if limit <= 0 {
		limit = 100 * 1024 * 1024
	}
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := master.Read(b)
			if n > 0 && written < limit {
				seq++
				row, _ := json.Marshal(map[string]interface{}{"sequence": seq, "data": base64.StdEncoding.EncodeToString(b[:n]), "timestamp": time.Now().UTC().Format(time.RFC3339Nano)})
				log.Write(append(row, '\n'))
				log.Sync()
				written += int64(len(row) + 1)
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				scan := bufio.NewScanner(c)
				if !scan.Scan() {
					return
				}
				var message control
				if json.Unmarshal(scan.Bytes(), &message) != nil {
					return
				}
				mu.Lock()
				last = time.Now()
				mu.Unlock()
				switch message.Type {
				case "input":
					data, _ := base64.StdEncoding.DecodeString(message.Data)
					master.Write(data)
				case "resize":
					size := [4]uint16{message.Rows, message.Cols, 0, 0}
					ioctl(master.Fd(), 0x5414, unsafe.Pointer(&size))
				case "terminate":
					syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
				}
				fmt.Fprintln(c, "ok")
			}()
		}
	}()
	go func() {
		idle, _ := strconv.Atoi(os.Getenv("AWE_SESSION_IDLE_SECONDS"))
		if idle <= 0 {
			idle = 3600
		}
		timeout, _ := strconv.Atoi(os.Getenv("AWE_EXECUTION_TIMEOUT"))
		start := time.Now()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stopped:
				return
			case <-tick.C:
				mu.Lock()
				elapsed := time.Since(last)
				mu.Unlock()
				if elapsed > time.Duration(idle)*time.Second || (timeout > 0 && time.Since(start) > time.Duration(timeout)*time.Second) {
					syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					return
				}
			}
		}
	}()
	err := cmd.Wait()
	close(stopped)
	code := 0
	if err != nil {
		code = cmd.ProcessState.ExitCode()
	}
	status, _ := json.Marshal(map[string]interface{}{"exit_code": code, "exited_at": time.Now().UTC().Format(time.RFC3339Nano), "transcript_truncated": written >= limit})
	os.WriteFile("/output/.awe-terminal-exit.json", status, 0644)
	// Let the output reader finish draining the PTY before the container exits.
	time.Sleep(100 * time.Millisecond)
	return nil
}
