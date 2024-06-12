package transport

import (
	"net"

	"github.com/ameshkov/dnscrypt/v2"
	"github.com/charmbracelet/log"
	"github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
	"github.com/wzshiming/socks5"
)

type DNSCrypt struct {
	Common
	ServerStamp string
	TCP         bool // default false (UDP)
	UDPSize     int

	// ServerStamp takes precedence if set
	PublicKey    string
	ProviderName string

	resolver *dnscrypt.ResolverInfo
	client   *dnscrypt.Client

	conn net.Conn
}

func (d *DNSCrypt) setup() error {
	if d.client == nil || d.resolver == nil || !d.ReuseConn {
		d.client = &dnscrypt.Client{
			UDPSize: d.UDPSize,
		}

		if d.TCP {
			d.client.Net = "tcp"
		} else {
			d.client.Net = "udp"
		}

		if d.ServerStamp == "" {
			stamp, err := dnsstamps.NewDNSCryptServerStampFromLegacy(d.Server, d.PublicKey, d.ProviderName, 0)
			if err != nil {
				log.Fatalf("failed to create stamp from provider information: %s", err)
				return err
			}
			d.ServerStamp = stamp.String()
			log.Debugf("Created DNS stamp from manual DNSCrypt configuration: %s", d.ServerStamp)
		}

		// Resolve server DNS stamp
		var dialErr error
		if len(d.Proxy) > 0 {
			stamp, err := dnsstamps.NewServerStampFromString(d.ServerStamp)
			if err != nil {
				return err
			}
			dialer, err := socks5.NewDialer(d.Proxy)
			if err != nil {
				return err
			}
			conn, err := dialer.Dial(d.client.Net, stamp.ServerAddrStr)
			if err != nil {
				return err
			}
			if !d.TCP {
				conn = &udpConn{UDPConn: conn.(*socks5.UDPConn), server: stamp.ServerAddrStr}
			}
			d.resolver, dialErr = d.client.DialWithConn(conn, d.ServerStamp)
			conn.Close()
		} else {
			d.resolver, dialErr = d.client.Dial(d.ServerStamp)
		}
		if dialErr != nil {
			log.Fatalf("failed to dial DNSCrypt server: %s", dialErr)
			return dialErr
		}
	}
	return nil
}

func (d *DNSCrypt) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	if err := d.setup(); err != nil {
		return nil, err
	}
	if len(d.Proxy) > 0 {
		if d.conn == nil {
			dialer, err := socks5.NewDialer(d.Proxy)
			if err != nil {
				return nil, err
			}
			d.conn, err = dialer.Dial(d.client.Net, d.resolver.ServerAddress)
			if err != nil {
				return nil, err
			}
		}
		return d.client.ExchangeConn(d.conn, msg, d.resolver)
	}
	return d.client.Exchange(msg, d.resolver)
}

func (d *DNSCrypt) Close() error {
	d.resolver = nil
	d.client = nil
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}
