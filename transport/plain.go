package transport

import (
	"time"

	"github.com/charmbracelet/log"
	"github.com/miekg/dns"
	"github.com/wzshiming/socks5"
)

// Plain makes a DNS query over TCP or UDP (with TCP fallback)
type Plain struct {
	Common
	PreferTCP bool
	EDNS      bool
	UDPBuffer uint16
	Timeout   time.Duration
}

func (p *Plain) Exchange(m *dns.Msg) (*dns.Msg, error) {
	tcpClient := dns.Client{Net: "tcp", Timeout: p.Timeout}

	var dialer *socks5.Dialer
	var err error
	if len(p.Proxy) > 0 {
		dialer, err = socks5.NewDialer(p.Proxy)
		if err != nil {
			return nil, err
		}
	}
	if p.PreferTCP {
		if len(p.Proxy) > 0 {
			conn, err := dialer.Dial("tcp", p.Server)
			if err != nil {
				return nil, err
			}
			reply, _, tcpErr := tcpClient.ExchangeWithConn(m, &dns.Conn{Conn: conn})
			return reply, tcpErr
		}
		reply, _, tcpErr := tcpClient.Exchange(m, p.Server)
		return reply, tcpErr
	}

	// Ensure an EDNS0 OPT record is present (if enabled) and advertises our UDP buffer size
	// so large UDP responses are either sized appropriately or marked truncated, allowing TCP retry.
	if p.EDNS {
		if opt := m.IsEdns0(); opt == nil {
			m.Extra = append(m.Extra, &dns.OPT{
				Hdr: dns.RR_Header{
					Name:   ".",
					Class:  p.UDPBuffer, // UDP payload size
					Rrtype: dns.TypeOPT,
				},
			})
		} else if opt.UDPSize() < p.UDPBuffer {
			opt.SetUDPSize(p.UDPBuffer)
		}
	}

	var reply *dns.Msg
	client := dns.Client{UDPSize: p.UDPBuffer, Timeout: p.Timeout}
	if len(p.Proxy) > 0 {
		conn, err1 := dialer.Dial("udp", p.Server)
		if err1 != nil {
			return nil, err1
		}
		reply, _, err = client.ExchangeWithConn(m, &dns.Conn{
			Conn: &udpConn{UDPConn: conn.(*socks5.UDPConn), server: p.Server},
		})
	} else {
		reply, _, err = client.Exchange(m, p.Server)
	}

	if reply != nil && reply.Truncated {
		log.Debugf("Truncated reply from %s for %s over UDP, retrying over TCP", p.Server, m.Question[0].String())
		if len(p.Proxy) > 0 {
			conn, err := dialer.Dial("tcp", p.Server)
			if err != nil {
				return nil, err
			}
			reply, _, err = tcpClient.ExchangeWithConn(m, &dns.Conn{Conn: conn})
		} else {
			reply, _, err = tcpClient.Exchange(m, p.Server)
		}
	}

	return reply, err
}

// Close is a no-op for the plain transport
func (p *Plain) Close() error {
	return nil
}

type udpConn struct {
	*socks5.UDPConn
	server string
}

func (c *udpConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, &udpAddr{address: c.server})
}

func (c *udpConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	if err != nil {
		return 0, err
	}
	return n, nil
}
