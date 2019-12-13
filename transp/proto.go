package transp

import "net"

type Proto uint8

const (
	Unknown Proto = iota
	UDP
	TCP
)

type Addr struct {
	addr net.Addr
}

func UDPAddr(address string) *Addr {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil
	}
	return &Addr{addr}
}

func (a Addr) Proto() Proto {
	switch a.addr.Network() {
	case "udp", "udp4", "udp6":
		return UDP
	case "tcp", "tcp4", "tcp6":
		return TCP
	default:
		return Unknown
	}
}

func (a Addr) IsUDP() bool { return a.Proto() == UDP }
func (a Addr) IsTCP() bool { return a.Proto() == TCP }
