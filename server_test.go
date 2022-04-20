package dns

import (
	"testing"
)

func TestServer(t *testing.T) {
	// server := NewServer(&ServerOptions{
	// 	port: 53,
	// })
	// client := NewClient()

	// cache := map[string][]string{}

	// server.Handle(func(host string) ([]string, error) {
	// 	if cache[host] != nil {
	// 		// logger.Info("lookup cache: %s", host)
	// 		return cache[host], nil
	// 	}

	// 	// logger.Info("lookup refresh: %s", host)
	// 	if host == "zero.com" {
	// 		cache[host] = []string{"6.6.6.6"}
	// 		return []string{"6.6.6.6"}, nil
	// 	}

	// 	if ips, err := client.LookUp(host); err != nil {
	// 		return nil, err
	// 	} else if len(ips) == 0 {
	// 		return nil, errors.New("cannot found ip for " + host)
	// 	} else {
	// 		cache[host] = ips
	// 		// logger.Info("found host(%s) %v\n", host, ips)
	// 		return ips, nil
	// 	}
	// })

	// server.Serve()
}
