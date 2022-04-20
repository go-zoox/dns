package main

import (
	"fmt"

	"github.com/go-zoox/dns"
	"github.com/go-zoox/kv"
	"github.com/go-zoox/logger"
)

func main() {
	server := dns.NewServer(&dns.ServerOptions{
		Port: 53,
	})
	client := dns.NewClient()

	cache := kv.NewMemory()

	server.Handle(func(host string, typ int) ([]string, error) {
		key := fmt.Sprintf("%s_%d", host, typ)
		// fmt.Println("key: ", key)
		if cache.Has(key) {
			// logger.Info("lookup cache: %s", host)
			return cache.Get(key).([]string), nil
		}

		// logger.Info("lookup refresh: %s", host)
		if host == "zero.com" {
			cache.Set(key, []string{"6.6.6.6"}, 5*60*1000)
			return []string{"6.6.6.6"}, nil
		}

		if ips, err := client.LookUp(host, &dns.LookUpOptions{Typ: typ}); err != nil {
			return nil, err
		} else {
			cache.Set(key, ips, 5*60*1000)
			logger.Info("found host(%s %d) %v", host, typ, ips)
			return ips, nil
		}
	})

	server.Serve()
}
