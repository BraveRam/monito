package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/BraveRam/monito/pkg/identity"
	"github.com/BraveRam/monito/pkg/storage"
)

// LiveAppRate represents live transfer rates for an app
type LiveAppRate struct {
	AppKey      string  `json:"app_key"`
	DisplayName string  `json:"display_name"`
	Category    string  `json:"category"`
	RateIn      float64 `json:"rate_in"`  // bytes per second
	RateOut     float64 `json:"rate_out"` // bytes per second
	TotalRate   float64 `json:"total_rate"`
}

// LiveStatus represents current real-time transfer rates across the system
type LiveStatus struct {
	Timestamp    time.Time     `json:"timestamp"`
	TotalRateIn  float64       `json:"total_rate_in"`
	TotalRateOut float64       `json:"total_rate_out"`
	TotalRate    float64       `json:"total_rate"`
	AppRates     []LiveAppRate `json:"app_rates"`
}

// AppUsageResponse wraps a traffic record with instantaneous rates
type AppUsageResponse struct {
	AppID       int64                 `json:"app_id"`
	Identity    *identity.AppIdentity `json:"identity"`
	Category    int                   `json:"category"`
	CategoryStr string                `json:"category_str"`
	BytesIn     int64                 `json:"bytes_in"`
	BytesOut    int64                 `json:"bytes_out"`
	TotalBytes  int64                 `json:"total_bytes"`
	PacketsIn   int64                 `json:"packets_in"`
	PacketsOut  int64                 `json:"packets_out"`
	RateIn      float64               `json:"rate_in"`
	RateOut     float64               `json:"rate_out"`
}

// CollectorStatus represents daemon health, diagnostics, and capacity
type CollectorStatus struct {
	ExcludedNamespacePackets uint64    `json:"excluded_namespace_packets"`
	NamespaceReadErrors      uint64    `json:"namespace_read_errors"`
	RecoveredSockets         uint64    `json:"recovered_sockets"`
	RecoveryErrors           uint64    `json:"recovery_errors"`
	UptimeSeconds            int64     `json:"uptime_seconds"`
	StartTime                time.Time `json:"start_time"`
	LastFlushTime            time.Time `json:"last_flush_time"`
	TotalIngressPackets      uint64    `json:"total_ingress_packets"`
	TotalEgressPackets       uint64    `json:"total_egress_packets"`
	SocketsRegistered        uint64    `json:"sockets_registered"`
	UnattributedIngress      uint64    `json:"unattributed_ingress"`
	UnattributedEgress       uint64    `json:"unattributed_egress"`
	MapErrors                uint64    `json:"map_errors"`
	ActiveAppCount           int       `json:"active_app_count"`
	Version                  string    `json:"version"`
}

// DoctorReport contains diagnostic system checks
type DoctorReport struct {
	KernelVersion   string   `json:"kernel_version"`
	CgroupV2Mounted bool     `json:"cgroup_v2_mounted"`
	BTFAvailable    bool     `json:"btf_available"`
	SELinuxStatus   string   `json:"selinux_status"`
	HasCAPBPF       bool     `json:"has_cap_bpf"`
	HasCAPNetAdmin  bool     `json:"has_cap_net_admin"`
	SocketReachable bool     `json:"socket_reachable"`
	DBWritable      bool     `json:"db_writable"`
	Warnings        []string `json:"warnings"`
}

// Client queries the versioned Monito collector API over Unix domain socket
type Client struct {
	httpClient *http.Client
	socketPath string
}

// NewClient creates a new Unix socket API client
func NewClient(socketPath string) *Client {
	return &Client{
		socketPath: socketPath,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

// DefaultSocketPath matches the system service. MONITO_SOCKET selects an
// explicitly configured user daemon without changing behavior based on UID.
func DefaultSocketPath() string {
	if path := os.Getenv("MONITO_SOCKET"); path != "" {
		return path
	}
	return "/run/monito/monito.sock"
}

// UserSocketPath is used by an explicitly launched unprivileged daemon.
func UserSocketPath() string {
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		return runtimeDir + "/monito.sock"
	}
	return os.Getenv("HOME") + "/.local/state/monito/monito.sock"
}

func (c *Client) get(endpoint string, target interface{}) error {
	resp, err := c.httpClient.Get("http://unix" + endpoint)
	if err != nil {
		return fmt.Errorf("collector connection failed (%s): %w", c.socketPath, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

// GetSummary retrieves day summary
func (c *Client) GetSummary(date string) (*storage.DaySummary, error) {
	var summary storage.DaySummary
	err := c.get(fmt.Sprintf("/api/v1/summary?date=%s", url.QueryEscape(date)), &summary)
	return &summary, err
}

// GetApps retrieves ranked application usage for a given date
func (c *Client) GetApps(date string, sort string, filter string) ([]AppUsageResponse, error) {
	var apps []AppUsageResponse
	endpoint := fmt.Sprintf("/api/v1/apps?date=%s&sort=%s&filter=%s",
		url.QueryEscape(date), url.QueryEscape(sort), url.QueryEscape(filter))
	err := c.get(endpoint, &apps)
	return apps, err
}

// GetHistory retrieves history points for an application
func (c *Client) GetHistory(appKey string, days int) ([]storage.AppHistoryPoint, error) {
	var pts []storage.AppHistoryPoint
	endpoint := fmt.Sprintf("/api/v1/history?app=%s&days=%s",
		url.QueryEscape(appKey), strconv.Itoa(days))
	err := c.get(endpoint, &pts)
	return pts, err
}

// GetLive retrieves real-time bandwidth rates
func (c *Client) GetLive() (*LiveStatus, error) {
	var live LiveStatus
	err := c.get("/api/v1/live", &live)
	return &live, err
}

// GetStatus retrieves collector health and diagnostics
func (c *Client) GetStatus() (*CollectorStatus, error) {
	var status CollectorStatus
	err := c.get("/api/v1/status", &status)
	return &status, err
}

// GetDoctor retrieves doctor system check results
func (c *Client) GetDoctor() (*DoctorReport, error) {
	var report DoctorReport
	err := c.get("/api/v1/doctor", &report)
	return &report, err
}
