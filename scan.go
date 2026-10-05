package main

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"
)

// expandTargets turns a host or CIDR into a list of hosts. A bare host is
// returned as-is; a CIDR is expanded to its usable addresses (capped).
func expandTargets(target string) ([]string, error) {
	if target == "" {
		return []string{"127.0.0.1"}, nil
	}
	if _, ipnet, err := net.ParseCIDR(target); err == nil {
		var hosts []string
		for ip := cloneIP(ipnet.IP.Mask(ipnet.Mask)); ipnet.Contains(ip); inc(ip) {
			hosts = append(hosts, ip.String())
			if len(hosts) > 4096 {
				return nil, fmt.Errorf("CIDR expands to more than 4096 hosts; narrow it")
			}
		}
		// drop network and broadcast for IPv4 /x where it makes sense
		if len(hosts) > 2 {
			hosts = hosts[1 : len(hosts)-1]
		}
		return hosts, nil
	}
	return []string{target}, nil
}

func scan(targets []string, concurrency int) []Finding {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		},
		// Never follow redirects to another host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	type job struct {
		host string
		svc  service
	}
	jobs := make(chan job)
	var mu sync.Mutex
	var findings []Finding
	var wg sync.WaitGroup

	if concurrency < 1 {
		concurrency = 64
	}
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if f := probe(client, j.host, j.svc); f != nil {
					mu.Lock()
					findings = append(findings, *f)
					mu.Unlock()
				}
			}
		}()
	}
	for _, host := range targets {
		for _, svc := range services {
			jobs <- job{host, svc}
		}
	}
	close(jobs)
	wg.Wait()

	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		return a.Port < b.Port
	})
	return findings
}

func cloneIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
