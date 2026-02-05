package client

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-zoox/dns/constants"
)

func TestClientLookUp(t *testing.T) {
	client := New()
	ip, err := client.LookUp("www.baidu.com")
	if err != nil {
		t.Error(err)
	}

	fmt.Println("IPv4:", ip)
	if len(ip) == 0 {
		t.Errorf("expect ip for www.baidu.com, but none")
	}

	ip, _ = client.lookUpIPv6("v216.whateverhappens.org")
	fmt.Println("IPv6:", ip)
}

func TestClientLookUp_DoT(t *testing.T) {
	// Test DNS-over-TLS with Cloudflare's DoT server
	client := New(&Options{
		Servers: []string{"tls://1.1.1.1"},
		Timeout: 10 * time.Second,
	})

	ip, err := client.LookUp("cloudflare.com")
	if err != nil {
		t.Skipf("DoT test skipped (may require network): %v", err)
		return
	}

	fmt.Println("DoT IPv4:", ip)
	if len(ip) == 0 {
		t.Errorf("expect ip for cloudflare.com via DoT, but none")
	}
}

func TestClientLookUp_DoT_IPv6(t *testing.T) {
	// Test DNS-over-TLS IPv6 lookup
	client := New(&Options{
		Servers: []string{"tls://1.1.1.1"},
		Timeout: 10 * time.Second,
	})

	ip, err := client.LookUp("cloudflare.com", &LookUpOptions{
		Typ: constants.QueryTypeIPv6,
	})
	if err != nil {
		t.Skipf("DoT IPv6 test skipped (may require network): %v", err)
		return
	}

	fmt.Println("DoT IPv6:", ip)
	// IPv6 may not always be available, so we don't fail if empty
}

func TestClientLookUp_DoT_WithPort(t *testing.T) {
	// Test DNS-over-TLS with explicit port
	client := New(&Options{
		Servers: []string{"tls://1.1.1.1:853"},
		Timeout: 10 * time.Second,
	})

	ip, err := client.LookUp("google.com")
	if err != nil {
		t.Skipf("DoT with port test skipped (may require network): %v", err)
		return
	}

	fmt.Println("DoT with port IPv4:", ip)
	if len(ip) == 0 {
		t.Errorf("expect ip for google.com via DoT, but none")
	}
}

func TestClientLookUp_DoT_Fallback(t *testing.T) {
	// Test DoT with fallback to plain DNS
	client := New(&Options{
		Servers: []string{
			"tls://invalid-dot-server.example.com:853", // Invalid server
			"8.8.8.8:53", // Fallback to plain DNS
		},
		Timeout: 5 * time.Second,
	})

	ip, err := client.LookUp("google.com")
	if err != nil {
		t.Skipf("DoT fallback test skipped (may require network): %v", err)
		return
	}

	fmt.Println("DoT fallback IPv4:", ip)
	if len(ip) == 0 {
		t.Errorf("expect ip for google.com via fallback, but none")
	}
}

func TestClientLookUp_MultipleDoTServers(t *testing.T) {
	// Test with multiple DoT servers
	client := New(&Options{
		Servers: []string{
			"tls://1.1.1.1",
			"tls://1.0.0.1",
		},
		Timeout: 10 * time.Second,
	})

	ip, err := client.LookUp("example.com")
	if err != nil {
		t.Skipf("Multiple DoT servers test skipped (may require network): %v", err)
		return
	}

	fmt.Println("Multiple DoT servers IPv4:", ip)
	if len(ip) == 0 {
		t.Errorf("expect ip for example.com via DoT, but none")
	}
}
