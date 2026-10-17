//go:build linux

package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/BraveRam/monito/pkg/api"
	"github.com/BraveRam/monito/pkg/identity"
	"github.com/BraveRam/monito/pkg/storage"
)

func binaries(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("MONITO_BIN_DIR"); dir != "" {
		return dir
	}
	dir := t.TempDir()
	for _, name := range []string{"monito", "monitod"} {
		cmd := exec.Command("go", "build", "-o", filepath.Join(dir, name), "./cmd/"+name)
		cmd.Dir = ".."
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", name, err, out)
		}
	}
	return dir
}

type daemonProcess struct {
	cmd  *exec.Cmd
	log  bytes.Buffer
	done bool
}

func startDaemon(t *testing.T, bin, db, socket string, mock bool) *daemonProcess {
	t.Helper()
	args := []string{"--db=" + db, "--socket=" + socket, "--flush-interval=30"}
	if mock {
		args = append(args, "--mock")
	}
	command := exec.Command(filepath.Join(bin, "monitod"), args...)
	if bounds := os.Getenv("MONITO_DAEMON_BOUNDING_SET"); bounds != "" && !mock {
		command = exec.Command("setpriv", append([]string{"--bounding-set=" + bounds, filepath.Join(bin, "monitod")}, args...)...)
	}
	d := &daemonProcess{cmd: command}
	d.cmd.Stdout, d.cmd.Stderr = &d.log, &d.log
	if err := d.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !d.done {
			d.cmd.Process.Kill()
			d.cmd.Wait()
		}
		if t.Failed() {
			t.Log(d.log.String())
		}
	})
	client := api.NewClient(socket)
	startupTimeout := 10 * time.Second
	if value := os.Getenv("MONITO_E2E_START_TIMEOUT"); value != "" {
		var err error
		startupTimeout, err = time.ParseDuration(value)
		if err != nil || startupTimeout <= 0 {
			t.Fatalf("invalid MONITO_E2E_START_TIMEOUT: %q", value)
		}
	}
	deadline := time.Now().Add(startupTimeout)
	for time.Now().Before(deadline) {
		if _, err := client.GetStatus(); err == nil {
			return d
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatal("daemon did not become ready")
	return nil
}
func (d *daemonProcess) stop(t *testing.T) {
	t.Helper()
	if err := d.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- d.cmd.Wait() }()
	select {
	case err := <-done:
		d.done = true
		if err != nil {
			t.Fatalf("daemon shutdown: %v\n%s", err, d.log.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("daemon did not shut down")
	}
}
func cli(t *testing.T, bin, socket string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	args = append(args, "--socket="+socket, "--json")
	cmd := exec.CommandContext(ctx, filepath.Join(bin, "monito"), args...)
	if os.Geteuid() == 0 {
		// Verify access from the invoking regular user, not just root.
		uid, _ := strconv.Atoi(os.Getenv("SUDO_UID"))
		gid, _ := strconv.Atoi(os.Getenv("SUDO_GID"))
		if uid == 0 {
			uid, gid = 65534, 65534
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI %v: %v\n%s", args, err, out)
	}
	if !json.Valid(out) {
		t.Fatalf("invalid JSON: %s", out)
	}
	return out
}

func TestMockEndToEnd(t *testing.T) {
	bin := binaries(t)
	dir := t.TempDir()
	db, socket := filepath.Join(dir, "usage.db"), filepath.Join(dir, "api.sock")
	store, err := storage.NewStorage(db)
	if err != nil {
		t.Fatal(err)
	}
	ident := &identity.AppIdentity{AppKey: "test:curl", DisplayName: "curl", Category: "cli_tool"}
	err = store.RecordUsage([]storage.IngestionRecord{{Identity: ident, Category: 2, BytesIn: 12345, BytesOut: 543}}, time.Local)
	store.Close()
	if err != nil {
		t.Fatal(err)
	}
	notifyPath := filepath.Join(dir, "notify.sock")
	notification, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: notifyPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer notification.Close()
	t.Setenv("NOTIFY_SOCKET", notifyPath)
	d := startDaemon(t, bin, db, socket, true)
	notification.SetReadDeadline(time.Now().Add(time.Second))
	ready := make([]byte, 256)
	n, _, err := notification.ReadFromUnix(ready)
	if err != nil || !strings.Contains(string(ready[:n]), "READY=1") {
		t.Fatalf("readiness=%q err=%v", ready[:n], err)
	}
	if _, err := api.NewClient(socket).GetStatus(); err != nil {
		t.Fatalf("READY before API: %v", err)
	}
	var summary storage.DaySummary
	if err := json.Unmarshal(cli(t, bin, socket, "today"), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.TotalBytes != 12888 {
		t.Fatalf("unexpected total: %+v", summary)
	}
	var apps []api.AppUsageResponse
	if err := json.Unmarshal(cli(t, bin, socket, "apps", "--filter=curl"), &apps); err != nil {
		t.Fatal(err)
	}
	if len(apps) != 1 || apps[0].Category != 2 || apps[0].CategoryStr != "external" {
		t.Fatalf("apps=%+v", apps)
	}
	cli(t, bin, socket, "history", "--app=test:curl", "--days=7")
	cli(t, bin, socket, "status")
	cli(t, bin, socket, "doctor")
	info, err := os.Stat(socket)
	if err != nil || info.Mode().Perm() != 0666 {
		t.Fatalf("socket permissions: %v %v", info, err)
	}
	// The real TUI runs under a pseudo-terminal and is driven through its keys.
	cmd := exec.Command("python3", "../scripts/tui-smoke.py", filepath.Join(bin, "monito"), socket)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("TUI smoke: %v\n%s", err, out)
	}
	d.stop(t)
	d = startDaemon(t, bin, db, socket, true)
	if err := json.Unmarshal(cli(t, bin, socket, "today"), &summary); err != nil || summary.TotalBytes != 12888 {
		t.Fatalf("restart lost history: %+v %v", summary, err)
	}
	d.stop(t)
}

const transferBytes = 2 * 1024 * 1024

// Helpers use distinct executable paths so server/client attribution is testable.
func TestWorkload(t *testing.T) {
	role := os.Getenv("MONITO_WORKLOAD")
	if role == "" {
		return
	}
	if role == "server" {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			panic(err)
		}
		fmt.Println(l.Addr().String())
		for {
			c, err := l.Accept()
			if err != nil {
				panic(err)
			}
			go func() {
				defer c.Close()
				for {
					c.SetDeadline(time.Now().Add(10 * time.Second))
					if _, err := io.CopyN(io.Discard, c, transferBytes); err != nil {
						return
					}
					if _, err := io.CopyN(c, zeroReader{}, transferBytes); err != nil {
						return
					}
				}
			}()
		}
	}
	persistent := os.Getenv("MONITO_PRECONNECT") == "1"
	connections := make([]net.Conn, 4)
	dial := func() net.Conn {
		c, err := net.DialTimeout("tcp4", os.Getenv("MONITO_ADDRESS"), 5*time.Second)
		if err != nil {
			panic(err)
		}
		return c
	}
	if persistent {
		for i := range connections {
			connections[i] = dial()
			defer connections[i].Close()
		}
	}
	fmt.Println("READY")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				c := connections[i]
				if !persistent {
					c = dial()
					defer c.Close()
				}
				c.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := io.CopyN(c, zeroReader{}, transferBytes); err != nil {
					panic(err)
				}
				if _, err := io.CopyN(io.Discard, c, transferBytes); err != nil {
					panic(err)
				}
			}(i)
		}
		wg.Wait()
		fmt.Println("DONE")
	}
	os.Exit(0)
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func helper(t *testing.T, dir, role, address string) (*exec.Cmd, io.WriteCloser, *bufio.Scanner) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "e2e-"+role)
	if err := os.WriteFile(path, data, 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, "-test.run=^TestWorkload$")
	if os.Geteuid() == 0 && os.Getenv("MONITO_EBPF_E2E") == "1" {
		uid, _ := strconv.Atoi(os.Getenv("SUDO_UID"))
		gid, _ := strconv.Atoi(os.Getenv("SUDO_GID"))
		if uid == 0 {
			uid, gid = 65534, 65534
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	}
	cmd.Env = append(os.Environ(), "MONITO_WORKLOAD="+role, "MONITO_ADDRESS="+address)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); cmd.Process.Kill(); cmd.Wait() })
	return cmd, in, bufio.NewScanner(out)
}

func TestKernelEndToEnd(t *testing.T)            { kernelEndToEnd(t, false) }
func TestKernelExistingConnections(t *testing.T) { kernelEndToEnd(t, true) }
func kernelEndToEnd(t *testing.T, preexisting bool) {
	if os.Getenv("MONITO_EBPF_E2E") != "1" {
		t.Skip("set MONITO_EBPF_E2E=1 and run with CAP_BPF+CAP_NET_ADMIN")
	}
	bin := binaries(t)
	dir, err := os.MkdirTemp("", "monito-kernel-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	db, socket := filepath.Join(dir, "usage.db"), filepath.Join(dir, "api.sock")
	var d *daemonProcess
	if !preexisting {
		d = startDaemon(t, bin, db, socket, false)
	}
	_, _, server := helper(t, dir, "server", "")
	if !server.Scan() {
		t.Fatal("server did not announce address")
	}
	address := server.Text()
	if preexisting {
		t.Setenv("MONITO_PRECONNECT", "1")
	}
	_, input, clientOutput := helper(t, dir, "client", address)
	if !clientOutput.Scan() || clientOutput.Text() != "READY" {
		t.Fatal("client not ready")
	}
	if preexisting {
		d = startDaemon(t, bin, db, socket, false)
	}
	cli(t, bin, socket, "status")
	client := api.NewClient(socket)
	if preexisting {
		// A recvmsg already blocked before attachment cannot be observed until
		// the app calls it again. Warm up existing connections before checking
		// subsequent accounting; historical unknown bytes remain unchanged.
		if _, err := fmt.Fprintln(input, "warmup"); err != nil {
			t.Fatal(err)
		}
		if !clientOutput.Scan() || clientOutput.Text() != "DONE" {
			t.Fatal("warmup failed")
		}
	}
	for phase := 0; phase < 2; phase++ {
		if _, err := fmt.Fprintln(input, "transfer"); err != nil {
			t.Fatal(err)
		}
		if !clientOutput.Scan() || clientOutput.Text() != "DONE" {
			t.Fatal("transfer failed")
		}
		if phase == 0 {
			// Synchronize just after a poll so phase two exercises final draining.
			deadline := time.Now().Add(5 * time.Second)
			seen := false
			for time.Now().Before(deadline) {
				live, err := client.GetLive()
				if err == nil && live.TotalRate > 0 {
					seen = true
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !seen {
				t.Fatal("live endpoint never reported generated traffic")
			}
		}
	}
	if preexisting {
		status, err := client.GetStatus()
		if err != nil || status.RecoveredSockets < 8 || status.RecoveryErrors != 0 {
			t.Fatalf("existing socket recovery: %+v %v", status, err)
		}
	}
	d.stop(t) // 30s flush interval; all database traffic must survive this path.
	store, err := storage.NewStorage(db)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	apps, err := store.GetAppsForDay(time.Now().Format("2006-01-02"), "total")
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"server", "client"} {
		key := "exec:" + filepath.Join(dir, "e2e-"+role)
		found := false
		for _, app := range apps {
			if app.Identity.AppKey != key && app.Identity.AppKey != "exec:e2e-"+role {
				continue
			}
			found = true
			minimum := int64(2 * 4 * transferBytes)
			if app.BytesIn < minimum || app.BytesOut < minimum {
				t.Errorf("%s undercounted: rx=%d tx=%d minimum=%d", role, app.BytesIn, app.BytesOut, minimum)
			}
			if app.Category != 0 {
				t.Errorf("loopback transfer category=%d", app.Category)
			}
		}
		if !found {
			t.Errorf("missing %s identity %s; apps=%+v", role, key, apps)
		}
	}
	// Reopen through the actual daemon/API to verify persistence after restart.
	d = startDaemon(t, bin, db, socket, true)
	out := cli(t, bin, socket, "apps")
	if !strings.Contains(string(out), "e2e-server") || !strings.Contains(string(out), "e2e-client") {
		t.Fatalf("restart lost apps: %s", out)
	}
	d.stop(t)
}
