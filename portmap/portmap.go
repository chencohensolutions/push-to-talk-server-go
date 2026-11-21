// Package portmap asks the home router to forward the server's ports to this machine (UPnP IGD, or NAT-PMP), so a
// phone on the internet can reach it without a port forwarded by hand (docs/discovery.md, "Opening the router").
// The mappings are asked for at start, renewed before their lease ends, and removed when the server stops. The
// router's outside address for the main TCP port joins the addresses the server publishes.
//
// A Mapper maps a list of ports, TCP or UDP: ptt-server's own TCP port, and later LiveKit's media ports (UDP 7882,
// TCP 7881), which must keep the same number outside and inside (Port.Exact).
package portmap

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Protocol is TCP or UDP.
type Protocol string

const (
	TCP Protocol = "TCP"
	UDP Protocol = "UDP"
)

// Port is one port to map: the protocol and the port on this machine.
type Port struct {
	Proto Protocol
	Port  uint16
	// Only the same number outside: when another machine holds it, the next ones aren't asked for. LiveKit's media
	// ports need this, since LiveKit tells the phones its own port number.
	Exact bool
}

func (p Port) String() string { return fmt.Sprintf("%s %d", p.Proto, p.Port) }

// Gateway is a router that maps ports: a UPnP IGD service or a NAT-PMP router.
type Gateway interface {
	// Kind names it in the log: "UPnP" or "NAT-PMP".
	Kind() string
	// Map forwards the external port to internal on this machine for lease, and gives the external port granted.
	Map(ctx context.Context, proto Protocol, internal, external uint16, lease time.Duration, description string) (uint16, error)
	// Unmap removes the mapping of external to internal.
	Unmap(ctx context.Context, proto Protocol, internal, external uint16) error
	// ExternalIP is the router's outside address.
	ExternalIP(ctx context.Context) (net.IP, error)
}

// Mapping is the router's forwarding of one of the server's ports, as last granted.
type Mapping struct {
	Kind         string
	Proto        Protocol
	InternalPort uint16
	ExternalIP   net.IP
	ExternalPort uint16
	// The router's outside address isn't public (carrier-grade NAT, or a second router in front): the mapping
	// works only up to there, and the internet still can't reach the server through it.
	Private bool
}

// Mapper keeps the server's ports mapped while it runs.
type Mapper struct {
	// The ports to map; the first is the server's own (Current, URL).
	Ports       []Port
	Description string
	// Finds the routers on the network; nil finds them with UPnP and NAT-PMP (Find).
	Find func(ctx context.Context) []Gateway

	mu      sync.Mutex
	current map[Port]*Mapping
}

var (
	// Lease is how long a mapping is asked for; it is renewed at half of it.
	Lease = time.Hour
	// RetryEvery is how often a server without a mapping asks again (a router restarted, UPnP turned on).
	RetryEvery = 10 * time.Minute
	// otherPorts is how many outside ports after the asked one are tried when that one is taken.
	otherPorts = uint16(4)
)

// NewMapper maps the server's own TCP port first, then the others.
func NewMapper(description string, ports ...Port) *Mapper {
	return &Mapper{Ports: ports, Description: description}
}

// Current is the mapping of the first port (the server's own), as last granted, or nil.
func (m *Mapper) Current() *Mapping {
	if len(m.Ports) == 0 {
		return nil
	}
	return m.Of(m.Ports[0])
}

// Of is the mapping of port, as last granted, or nil.
func (m *Mapper) Of(port Port) *Mapping {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.current[port]
	if c == nil {
		return nil
	}
	copied := *c
	return &copied
}

// All is every mapping granted now, in the order of Ports.
func (m *Mapper) All() []Mapping {
	var out []Mapping
	for _, p := range m.Ports {
		if c := m.Of(p); c != nil {
			out = append(out, *c)
		}
	}
	return out
}

// Run maps the ports, renews them, and removes them when ctx ends.
func (m *Mapper) Run(ctx context.Context) {
	find := m.Find
	if find == nil {
		find = Find
	}
	var gw Gateway
	warned := false
	for {
		wait := RetryEvery
		if gw != nil {
			if m.mapAll(ctx, gw) {
				wait = Lease / 2
			} else {
				if ctx.Err() == nil {
					log.Printf("Port mapping: renewing on %s failed; looking for the router again", gw.Kind())
				}
				m.clear()
				gw, wait = nil, time.Minute
				if wait > RetryEvery {
					wait = RetryEvery
				}
			}
		} else {
			gw = m.first(ctx, find)
			switch {
			case gw != nil:
				wait = Lease / 2
			case ctx.Err() == nil && !warned:
				warned = true
				log.Printf("Port mapping: no router on this network maps ports (UPnP and NAT-PMP off, or none answers); "+
					"forward %s by hand, or use IPv6. Asked again every %s.", m.portList(), RetryEvery)
			}
		}
		select {
		case <-ctx.Done():
			m.remove(gw)
			return
		case <-time.After(wait):
		}
	}
}

func (m *Mapper) portList() string {
	var names []string
	for _, p := range m.Ports {
		names = append(names, p.String())
	}
	return strings.Join(names, ", ")
}

// first maps the ports on the first of the routers found that maps any, and gives it.
func (m *Mapper) first(ctx context.Context, find func(context.Context) []Gateway) Gateway {
	ask, cancel := context.WithTimeout(ctx, 10*time.Second)
	gws := find(ask)
	cancel()
	for _, g := range gws {
		if m.mapAll(ctx, g) {
			return g
		}
		if ctx.Err() != nil {
			return nil
		}
	}
	return nil
}

// mapAll maps (or renews) every port on g, and reports whether g mapped any. A port it refuses is logged once and
// asked for again at the next renewal.
func (m *Mapper) mapAll(ctx context.Context, g Gateway) bool {
	mapped := false
	for _, p := range m.Ports {
		mapping, err := m.mapOn(ctx, g, p)
		if err != nil {
			if ctx.Err() != nil {
				return false
			}
			if m.Of(p) != nil {
				log.Printf("Port mapping: %s no longer forwards %s: %v", g.Kind(), p, err)
			} else {
				log.Printf("Port mapping: %s refused %s: %v", g.Kind(), p, err)
			}
			m.set(p, nil)
			continue
		}
		mapped = true
		m.report(mapping)
	}
	return mapped
}

// remove takes the mappings off gw when the server stops, so the router doesn't keep forwarding to nothing.
func (m *Mapper) remove(gw Gateway) {
	if gw == nil {
		return
	}
	stop, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, c := range m.All() {
		if err := gw.Unmap(stop, c.Proto, c.InternalPort, c.ExternalPort); err == nil {
			log.Printf("Port mapping: removed %s %d from the router", c.Proto, c.ExternalPort)
		}
	}
	m.clear()
}

func (m *Mapper) mapOn(ctx context.Context, g Gateway, p Port) (*Mapping, error) {
	ask, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	external := p.Port
	before := m.Of(p)
	if before != nil {
		external = before.ExternalPort
	}
	got, err := g.Map(ask, p.Proto, p.Port, external, Lease, m.Description)
	if err != nil && before == nil && !p.Exact {
		// Another machine may hold the outside port already (UPnP error 718, ConflictInMappingEntry): a second
		// server at home, say. Ask for the next few; the port granted is the one published.
		for next := uint16(1); next <= otherPorts && err != nil && ask.Err() == nil && external+next > external; next++ {
			got, err = g.Map(ask, p.Proto, p.Port, external+next, Lease, m.Description)
		}
	}
	if err != nil {
		return nil, err
	}
	if p.Exact && got != p.Port {
		// NAT-PMP may grant another port than the one asked for.
		g.Unmap(ask, p.Proto, p.Port, got)
		return nil, fmt.Errorf("the router offered outside port %d, and %s needs %d", got, p, p.Port)
	}
	ip, err := g.ExternalIP(ask)
	if err != nil {
		return nil, fmt.Errorf("mapped, but the router didn't say its outside address: %w", err)
	}
	return &Mapping{Kind: g.Kind(), Proto: p.Proto, InternalPort: p.Port, ExternalIP: ip, ExternalPort: got,
		Private: !Public(ip)}, nil
}

// report keeps mapping, and logs it when it changed.
func (m *Mapper) report(mapping *Mapping) {
	port := Port{}
	for _, p := range m.Ports {
		if p.Proto == mapping.Proto && p.Port == mapping.InternalPort {
			port = p
		}
	}
	before := m.Of(port)
	m.set(port, mapping)
	if before != nil && before.ExternalIP.Equal(mapping.ExternalIP) && before.ExternalPort == mapping.ExternalPort {
		return
	}
	at := mapping.Proto.lower() + " " + net.JoinHostPort(mapping.ExternalIP.String(), fmt.Sprint(mapping.ExternalPort))
	if mapping.Private {
		log.Printf("Port mapping: the router (%s) forwards %s to this server, but %s isn't a public address: the "+
			"internet can't reach the server through it (carrier-grade NAT, or another router in front). Ask the ISP "+
			"for a public IPv4 address, or use IPv6.", mapping.Kind, at, mapping.ExternalIP)
		return
	}
	log.Printf("Port mapping: the router (%s) forwards %s to this server", mapping.Kind, at)
}

func (p Protocol) lower() string { return strings.ToLower(string(p)) }

func (m *Mapper) set(port Port, mapping *Mapping) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil {
		m.current = map[Port]*Mapping{}
	}
	if mapping == nil {
		delete(m.current, port)
		return
	}
	m.current[port] = mapping
}

func (m *Mapper) clear() {
	m.mu.Lock()
	m.current = nil
	m.mu.Unlock()
}

// Public is an address the internet can reach: not private, shared (100.64.0.0/10), loopback or link-local.
func Public(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	return a.IsGlobalUnicast() && !a.IsPrivate() && !netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

// URL is the server's address on the internet through a TCP mapping, or "" when the internet can't reach it there
// (or it isn't TCP).
func (m *Mapping) URL() string {
	if m == nil || m.Private || m.Proto != TCP {
		return ""
	}
	return "https://" + net.JoinHostPort(m.ExternalIP.String(), fmt.Sprint(m.ExternalPort))
}
