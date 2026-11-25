package probe

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func startServer(t *testing.T) (*Server, string) {
	t.Helper()
	// Find a port free for both TCP and UDP.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	s := NewServer()
	go s.Serve(addr)
	time.Sleep(100 * time.Millisecond)
	return s, addr
}

func TestLatencyAndBandwidth(t *testing.T) {
	s, addr := startServer(t)
	tok := NewToken()
	s.Open(tok, time.Minute)
	ctx := context.Background()

	r, err := Latency(ctx, addr, tok, 20, 5*time.Millisecond, 64)
	if err != nil {
		t.Fatal(err)
	}
	if r.Received != 20 || r.Loss() != 0 || r.Avg <= 0 || r.Min > r.Max {
		t.Errorf("unexpected latency result %+v", r)
	}

	for _, dir := range []Direction{Upload, Download} {
		bps, err := Bandwidth(ctx, addr, tok, dir, 300*time.Millisecond, 2)
		if err != nil {
			t.Fatalf("%c: %v", dir, err)
		}
		if bps < 1e6 {
			t.Errorf("%c: implausibly slow loopback: %.0f bit/s", dir, bps)
		}
	}
}

func TestRejectsUnknownToken(t *testing.T) {
	s, addr := startServer(t)
	s.Open(NewToken(), time.Minute)
	if _, err := Latency(context.Background(), addr, NewToken(), 3, 5*time.Millisecond, 64); err == nil {
		t.Error("probe answered without a valid token")
	}
	if _, err := Bandwidth(context.Background(), addr, NewToken(), Download, 200*time.Millisecond, 1); err == nil {
		t.Error("bandwidth served without a valid token")
	}
}

type countConn struct {
	net.Conn
	r, w *atomic.Int64
}

func (c countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.r.Add(int64(n))
	return n, err
}

func (c countConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.w.Add(int64(n))
	return n, err
}

func (c countConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func TestBandwidthByteLimit(t *testing.T) {
	s, addr := startServer(t)
	tok := NewToken()
	s.Open(tok, time.Minute)
	ctx := context.Background()

	const limit = 2 << 20 // 2 MiB
	const streams = 4

	cases := []struct {
		name        string
		dir         Direction
		serverLimit bool
	}{
		{"upload", Upload, true},
		{"download_server_limit", Download, true},
		{"download_client_fallback", Download, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rBytes, wBytes atomic.Int64
			dial := func(ctx context.Context) (net.Conn, error) {
				var dl net.Dialer
				c, err := dl.DialContext(ctx, "tcp", addr)
				if err != nil {
					return nil, err
				}
				return countConn{Conn: c, r: &rBytes, w: &wBytes}, nil
			}
			start := time.Now()
			bps, err := BandwidthOverLimit(ctx, dial, tok, tc.dir, BandwidthOptions{
				Duration:    10 * time.Second,
				Streams:     streams,
				MaxBytes:    limit,
				ServerLimit: tc.serverLimit,
			})
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("BandwidthOverLimit: %v", err)
			}
			if bps < 1e6 {
				t.Errorf("implausibly slow loopback: %.0f bit/s", bps)
			}
			// Must stop early on byte limit, not run for the 10s safety duration.
			if elapsed > 3*time.Second {
				t.Errorf("took %v; expected to stop well before 10s duration", elapsed)
			}
			switch tc.dir {
			case Upload:
				// Payload + streams*(21-byte header)
				hdr := int64(streams * (tokenLen + 5))
				got := wBytes.Load() - hdr
				if got != limit {
					t.Errorf("uploaded %d payload bytes, want exact %d", got, limit)
				}
			case Download:
				got := rBytes.Load()
				if tc.serverLimit {
					if got != limit {
						t.Errorf("downloaded %d bytes, want exact %d", got, limit)
					}
				} else {
					// Fallback stops at or slightly above limit across concurrent readers
					// (at most one read buffer per extra stream).
					if got < limit || got > limit+int64(streams)*(128<<10) {
						t.Errorf("downloaded %d bytes, want near %d", got, limit)
					}
				}
			}
		})
	}
}
