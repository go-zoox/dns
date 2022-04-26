package dns

import (
	"fmt"
	"testing"
)

func TestClientLookUp(t *testing.T) {
	client := NewClient()
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
