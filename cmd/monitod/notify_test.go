package main

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNotifyReady(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := notifyReady(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "notify.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	if err := notifyReady(); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 256)
	n, _, err := conn.ReadFromUnix(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "READY=1") {
		t.Fatalf("message=%q err=%v", buf[:n], err)
	}
}
