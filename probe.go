package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type severity int

const (
	low severity = iota + 1
	medium
	high
	critical
)

func (s severity) String() string {
	switch s {
	case critical:
		return "critical"
	case high:
		return "high"
	case medium:
		return "medium"
	}
	return "low"
}

func (s severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Finding is one exposed service on one host.
type Finding struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Service  string   `json:"service"`
	Severity severity `json:"severity"`
	Auth     bool     `json:"auth_required"`
	Risk     string   `json:"risk"`
	URL      string   `json:"url"`
}

// probe checks one host for one service. It returns a Finding when the service
// is present, with Auth set to whether it demanded authentication.
func probe(client *http.Client, host string, svc service) *Finding {
	url := "http://" + net.JoinHostPort(host, itoa(svc.port)) + svc.probePath
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "ajar/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// 401/403 means the service is there but asking for auth: good, not a finding.
	authRequired := resp.StatusCode == 401 || resp.StatusCode == 403
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	text := string(body)

	if !matches(text, svc.bodyNeedles) {
		return nil
	}
	if authRequired {
		return nil
	}
	return &Finding{
		Host: host, Port: svc.port, Service: svc.name, Severity: svc.severity,
		Auth: false, Risk: svc.risk, URL: url,
	}
}

func matches(body string, needles []string) bool {
	for _, n := range needles {
		if !strings.Contains(body, n) {
			return false
		}
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
