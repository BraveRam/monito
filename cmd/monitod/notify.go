package main

import (
	"fmt"
	"net"
	"os"
)

// systemd waits for this message with Type=notify. Direct invocations work
// without NOTIFY_SOCKET, and abstract Linux socket addresses are supported.
func notifyReady() error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("connect readiness socket: %w", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("READY=1\nSTATUS=Collecting network traffic")); err != nil {
		return fmt.Errorf("signal readiness: %w", err)
	}
	return nil
}
