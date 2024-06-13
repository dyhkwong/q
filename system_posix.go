//go:build !windows

package main

import (
	"github.com/miekg/dns"
	"github.com/charmbracelet/log"
)

func getSystemDNS() (server string) {
	log.Debugf("No server specified or %s set, using /etc/resolv.conf", defaultServerVar)
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(conf.Servers) == 0 {
		return
	}
	server = conf.Servers[0]
	log.Debugf("found server %s from /etc/resolv.conf", server)
	return
}
