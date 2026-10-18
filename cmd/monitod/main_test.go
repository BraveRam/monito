package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/BraveRam/monito/pkg/bpf"
	"github.com/BraveRam/monito/pkg/identity"
	"github.com/BraveRam/monito/pkg/storage"
)

type finalCollector struct {
	stopped bool
	deltas  []bpf.FlowDelta
}

func (f *finalCollector) StopAccounting() error                { f.stopped = true; return nil }
func (f *finalCollector) ReadCounters() bpf.DiagnosticCounters { return bpf.DiagnosticCounters{} }
func (f *finalCollector) DrainDeltas() ([]bpf.FlowDelta, error) {
	if !f.stopped {
		return nil, nil
	}
	if f.deltas != nil {
		return f.deltas, nil
	}
	return []bpf.FlowDelta{{PID: 0, Category: bpf.CategoryExternal, RxBytes: 600, TxBytes: 200}}, nil
}

func TestFailedFlushRetainsRecordsForRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.db")
	store, err := storage.NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	d := &collectorDaemon{store: store, pendingRecords: []storage.IngestionRecord{{
		Identity: &identity.AppIdentity{AppKey: "test", DisplayName: "test"}, Category: 2, BytesIn: 123,
	}}}
	store.Close()
	if err := d.flush(); err == nil {
		t.Fatal("expected closed DB error")
	}
	if len(d.pendingRecords) != 1 || !d.lastFlushTime.IsZero() {
		t.Fatal("failed flush discarded records or reported success")
	}
	store, err = storage.NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	d.store = store
	if err := d.flush(); err != nil {
		t.Fatal(err)
	}
	if len(d.pendingRecords) != 0 || d.lastFlushTime.IsZero() {
		t.Fatal("successful flush did not update state")
	}
	if err := d.flush(); err != nil {
		t.Fatal(err)
	}
	summary, err := store.GetDaySummary(time.Now().Format("2006-01-02"))
	if err != nil || summary.TotalBytes != 123 {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
}

func TestFinalSnapshotPersistsUndrainedTraffic(t *testing.T) {
	store, err := storage.NewStorage(filepath.Join(t.TempDir(), "usage.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	collector := &finalCollector{}
	d := &collectorDaemon{store: store, resolver: identity.NewResolver(), bpfCollector: collector}
	if err := collector.StopAccounting(); err != nil {
		t.Fatal(err)
	}
	if err := d.poll(time.Now(), 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := d.GetLiveStatus().TotalRate; got != 400 {
		t.Fatalf("rate=%v want 400 B/s", got)
	}
	if err := d.flush(); err != nil {
		t.Fatal(err)
	}
	summary, err := store.GetDaySummary(time.Now().Format("2006-01-02"))
	if err != nil || summary.TotalBytes != 800 {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
}

func TestLiveRatesExcludeLocalTraffic(t *testing.T) {
	store, err := storage.NewStorage(filepath.Join(t.TempDir(), "usage.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	collector := &finalCollector{stopped: true, deltas: []bpf.FlowDelta{
		{Category: bpf.CategoryExternal, RxBytes: 600, TxBytes: 200},
		{Category: bpf.CategoryLoopback, RxBytes: 9000, TxBytes: 9000},
		{Category: bpf.CategoryPrivate, RxBytes: 7000, TxBytes: 7000},
		{Category: bpf.CategoryUnknown, RxBytes: 5000, TxBytes: 5000},
	}}
	d := &collectorDaemon{store: store, resolver: identity.NewResolver(), bpfCollector: collector}
	if err := d.poll(time.Now(), 2*time.Second); err != nil {
		t.Fatal(err)
	}
	live := d.GetLiveStatus()
	if live.TotalRateIn != 300 || live.TotalRateOut != 100 || live.TotalRate != 400 || len(live.AppRates) != 1 || live.AppRates[0].TotalRate != 400 {
		t.Fatalf("local rates leaked: %+v", live)
	}
	if len(d.pendingRecords) != 4 {
		t.Fatal("discarded raw history")
	}
	collector.deltas = collector.deltas[1:]
	if err := d.poll(time.Now(), time.Second); err != nil {
		t.Fatal(err)
	}
	live = d.GetLiveStatus()
	if live.TotalRate != 0 || len(live.AppRates) != 0 {
		t.Fatalf("local-only traffic leaked: %+v", live)
	}
}
