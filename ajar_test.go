package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func testClient() *http.Client {
	return &http.Client{Timeout: 3 * time.Second}
}

func hostPort(t *testing.T, ts *httptest.Server) (string, int) {
	t.Helper()
	u, _ := url.Parse(ts.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func TestProbeDetectsExposedService(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.Write([]byte(`{"models":[{"name":"llama3"}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()
	host, port := hostPort(t, ts)

	svc := service{name: "Ollama", port: port, probePath: "/api/tags",
		bodyNeedles: []string{"\"models\""}, severity: high}
	f := probe(testClient(), host, svc)
	if f == nil {
		t.Fatal("exposed service not detected")
	}
	if f.Auth {
		t.Error("should be marked as no-auth")
	}
	if f.Service != "Ollama" {
		t.Errorf("service = %q", f.Service)
	}
}

func TestProbeSkipsAuthenticated(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"models":[]}`))
	}))
	defer ts.Close()
	host, port := hostPort(t, ts)
	svc := service{name: "Ollama", port: port, probePath: "/api/tags",
		bodyNeedles: []string{"\"models\""}, severity: high}
	if f := probe(testClient(), host, svc); f != nil {
		t.Error("auth-protected service should not be a finding")
	}
}

func TestProbeSkipsWrongBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>some other web app</html>"))
	}))
	defer ts.Close()
	host, port := hostPort(t, ts)
	svc := service{name: "Ollama", port: port, probePath: "/api/tags",
		bodyNeedles: []string{"\"models\""}, severity: high}
	if f := probe(testClient(), host, svc); f != nil {
		t.Error("non-matching body should not be a finding")
	}
}

func TestProbeNoServer(t *testing.T) {
	svc := service{name: "x", port: 1, probePath: "/", bodyNeedles: []string{"y"}, severity: low}
	if f := probe(testClient(), "127.0.0.1", svc); f != nil {
		t.Error("closed port should not be a finding")
	}
}

func TestExpandTargetsDefault(t *testing.T) {
	hosts, err := expandTargets("")
	if err != nil || len(hosts) != 1 || hosts[0] != "127.0.0.1" {
		t.Errorf("default = %v, %v", hosts, err)
	}
}

func TestExpandTargetsSingleHost(t *testing.T) {
	hosts, _ := expandTargets("192.168.1.10")
	if len(hosts) != 1 || hosts[0] != "192.168.1.10" {
		t.Errorf("single host = %v", hosts)
	}
}

func TestExpandTargetsCIDR(t *testing.T) {
	hosts, err := expandTargets("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	// /30 has 4 addresses; network and broadcast dropped -> 2 usable
	if len(hosts) != 2 || hosts[0] != "192.168.1.1" || hosts[1] != "192.168.1.2" {
		t.Errorf("CIDR /30 = %v", hosts)
	}
}

func TestExpandTargetsCIDRTooBig(t *testing.T) {
	if _, err := expandTargets("10.0.0.0/8"); err == nil {
		t.Error("huge CIDR should error")
	}
}

func TestScanAndExitCode(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.Write([]byte(`{"object":"list","data":[{"id":"gpt"}]}`))
		}
	}))
	defer ts.Close()
	host, port := hostPort(t, ts)
	// Point one service at the test server.
	saved := services
	services = []service{{name: "vLLM", port: port, probePath: "/v1/models",
		bodyNeedles: []string{"\"data\"", "\"object\""}, risk: "test", severity: high}}
	defer func() { services = saved }()

	findings := scan([]string{host}, 8)
	if len(findings) != 1 {
		t.Fatalf("findings = %d", len(findings))
	}
}

func TestItoa(t *testing.T) {
	for _, n := range []int{0, 7, 80, 11434, 65535} {
		if itoa(n) != strconv.Itoa(n) {
			t.Errorf("itoa(%d) = %q", n, itoa(n))
		}
	}
}
