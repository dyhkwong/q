package transport

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/miekg/dns"
	"github.com/wzshiming/socks5"
)

// TLS makes a DNS query over TLS
type TLS struct {
	Common
	TLSConfig *tls.Config
	conn      *tls.Conn
}

func (t *TLS) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	if t.conn == nil || !t.ReuseConn {
		var err error
		if len(t.Proxy) > 0 {
			host, _, err := net.SplitHostPort(t.Server)
			if err != nil {

				return nil, err
			}
			dialer, err := socks5.NewDialer(t.Proxy)
			if err != nil {
				return nil, err
			}
			conn, err := dialer.Dial("tcp", t.Server)
			if err != nil {
				return nil, err
			}
			t.TLSConfig.ServerName = host
			t.conn = tls.Client(conn, t.TLSConfig)
		} else {
			t.conn, err = tls.DialWithDialer(
				&net.Dialer{},
				"tcp",
				t.Server,
				t.TLSConfig,
			)
			if err != nil {
				return nil, err
			}
		}
		if err = t.conn.Handshake(); err != nil {
			return nil, err
		}
	}

	c := dns.Conn{Conn: t.conn}
	if err := c.WriteMsg(msg); err != nil {
		return nil, fmt.Errorf("write msg to %s: %v", t.Server, err)
	}

	return c.ReadMsg()
}

// Close closes the TLS connection
func (t *TLS) Close() error {
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}
