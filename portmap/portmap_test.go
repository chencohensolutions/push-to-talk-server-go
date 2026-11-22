package portmap

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeGateway is a router: it maps what it is asked unless refuse is set, and counts the calls.
type fakeGateway struct {
	kind     string
	ip       net.IP
	external uint16 // the port it grants; 0 grants the one asked for

	mu       sync.Mutex
	refuse   bool
	taken    map[Port]bool // outside ports another machine holds
	refused  Protocol      // a protocol it never maps
	maps     int
	unmapped []Port          // outside ports
	mapped   map[Port]uint16 // outside port → inside port, as asked now
}

func (g *fakeGateway) Kind() string { return g.kind }

func (g *fakeGateway) Map(_ context.Context, proto Protocol, internal, external uint16, _ time.Duration, _ string) (uint16, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.refuse || g.taken[Port{Proto: proto, Port: external}] || proto == g.refused {
		return 0, errors.New("refused")
	}
	g.maps++
	if g.external != 0 {
		external = g.external
	}
	if g.mapped == nil {
		g.mapped = map[Port]uint16{}
	}
	g.mapped[Port{Proto: proto, Port: external}] = internal
	return external, nil
}

func (g *fakeGateway) Unmap(_ context.Context, proto Protocol, internal, external uint16) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.unmapped = append(g.unmapped, Port{Proto: proto, Port: external})
	delete(g.mapped, Port{Proto: proto, Port: external})
	return nil
}

func (g *fakeGateway) ExternalIP(context.Context) (net.IP, error) { return g.ip, nil }

func (g *fakeGateway) counts() (int, []Port) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.maps, append([]Port(nil), g.unmapped...)
}

var serverPort = Port{Proto: TCP, Port: 56400}

func shortTimes(t *testing.T) {
	lease, retry := Lease, RetryEvery
	Lease, RetryEvery = 40*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { Lease, RetryEvery = lease, retry })
}

// run runs m until the test ends, and waits for it to stop before the times are put back.
func run(t *testing.T, m *Mapper) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); !ok(); {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestMapsRenewsAndRemovesOnStop(t *testing.T) {
	shortTimes(t)
	refusing := &fakeGateway{kind: "UPnP", ip: net.IPv4(203, 0, 113, 7), refuse: true}
	router := &fakeGateway{kind: "NAT-PMP", ip: net.IPv4(203, 0, 113, 7), external: 40123}
	m := &Mapper{Ports: []Port{serverPort}, Find: func(context.Context) []Gateway { return []Gateway{refusing, router} }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()

	waitFor(t, "a mapping", func() bool { return m.Current() != nil })
	c := m.Current()
	if c.Kind != "NAT-PMP" || c.ExternalPort != 40123 || c.Private || c.URL() != "https://203.0.113.7:40123" {
		t.Fatalf("mapping: %+v (%s)", c, c.URL())
	}
	waitFor(t, "renewals", func() bool { n, _ := router.counts(); return n >= 3 })

	cancel()
	<-done
	if _, unmapped := router.counts(); len(unmapped) != 1 || unmapped[0] != (Port{TCP, 40123, false}) {
		t.Fatalf("unmapped on stop: %v", unmapped)
	}
	if _, unmapped := refusing.counts(); len(unmapped) != 0 {
		t.Fatalf("the router that refused was asked to unmap: %v", unmapped)
	}
	if m.Current() != nil {
		t.Fatalf("still a mapping after stop: %+v", m.Current())
	}
}

func TestFindsTheRouterLaterAndAgainAfterItForgets(t *testing.T) {
	shortTimes(t)
	router := &fakeGateway{kind: "UPnP", ip: net.IPv4(198, 51, 100, 2)}
	var mu sync.Mutex
	present := false
	m := &Mapper{Ports: []Port{serverPort}, Find: func(context.Context) []Gateway {
		mu.Lock()
		defer mu.Unlock()
		if !present {
			return nil
		}
		return []Gateway{router}
	}}
	run(t, m)

	time.Sleep(50 * time.Millisecond)
	if m.Current() != nil {
		t.Fatal("a mapping with no router")
	}
	mu.Lock()
	present = true // UPnP turned on, or the router came back
	mu.Unlock()
	waitFor(t, "a mapping once the router answers", func() bool { return m.Current() != nil })

	router.mu.Lock()
	router.refuse = true // the router restarted and refuses the renewal
	router.mu.Unlock()
	waitFor(t, "the mapping dropped", func() bool { return m.Current() == nil })
	router.mu.Lock()
	router.refuse = false
	router.mu.Unlock()
	waitFor(t, "a mapping again", func() bool { return m.Current() != nil })
}

func TestPrivateOutsideAddress(t *testing.T) {
	shortTimes(t)
	router := &fakeGateway{kind: "UPnP", ip: net.IPv4(100, 72, 1, 9)} // carrier-grade NAT
	m := &Mapper{Ports: []Port{serverPort}, Find: func(context.Context) []Gateway { return []Gateway{router} }}
	run(t, m)
	waitFor(t, "a mapping", func() bool { return m.Current() != nil })
	if c := m.Current(); !c.Private || c.URL() != "" {
		t.Fatalf("a mapping behind carrier-grade NAT: %+v, url %q", c, c.URL())
	}
}

func TestPublic(t *testing.T) {
	for ip, want := range map[string]bool{
		"203.0.113.7": true, "8.8.8.8": true, "2001:4860::8888": true,
		"192.168.1.1": false, "10.0.0.1": false, "172.16.5.4": false, "100.64.0.1": false, "100.127.255.254": false,
		"127.0.0.1": false, "169.254.1.1": false, "fd00::1": false, "fe80::1": false,
	} {
		if got := Public(net.ParseIP(ip)); got != want {
			t.Errorf("Public(%s) = %v, want %v", ip, got, want)
		}
	}
	var none *Mapping
	if none.URL() != "" {
		t.Error("a nil mapping has a URL")
	}
}

func TestTakesTheNextPortWhenAnotherMachineHasIt(t *testing.T) {
	shortTimes(t)
	router := &fakeGateway{kind: "UPnP", ip: net.IPv4(203, 0, 113, 7), taken: map[Port]bool{{TCP, 56400, false}: true, {TCP, 56401, false}: true}}
	m := &Mapper{Ports: []Port{serverPort}, Find: func(context.Context) []Gateway { return []Gateway{router} }}
	run(t, m)
	waitFor(t, "a mapping", func() bool { return m.Current() != nil })
	if c := m.Current(); c.ExternalPort != 56402 || c.URL() != "https://203.0.113.7:56402" {
		t.Fatalf("mapping: %+v", c)
	}
	waitFor(t, "a renewal", func() bool { n, _ := router.counts(); return n >= 2 })
	if c := m.Current(); c == nil || c.ExternalPort != 56402 {
		t.Fatalf("after renewing: %+v", c)
	}
}

// The server's TCP port and LiveKit's media ports map together; a UDP port keeps its number outside, and one the
// router refuses doesn't stop the others.
func TestMapsTCPAndUDPTogether(t *testing.T) {
	shortTimes(t)
	media := Port{Proto: UDP, Port: 7882, Exact: true}
	fallback := Port{Proto: TCP, Port: 7881, Exact: true}
	router := &fakeGateway{kind: "UPnP", ip: net.IPv4(203, 0, 113, 7)}
	m := NewMapper("ptt-server", serverPort, media, fallback)
	m.Find = func(context.Context) []Gateway { return []Gateway{router} }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	waitFor(t, "three mappings", func() bool { return len(m.All()) == 3 })
	if c := m.Of(media); c.Proto != UDP || c.ExternalPort != 7882 || c.URL() != "" {
		t.Fatalf("the UDP mapping: %+v (%q)", c, c.URL())
	}
	if c := m.Current(); c.Proto != TCP || c.URL() != "https://203.0.113.7:56400" {
		t.Fatalf("the server's own mapping: %+v", c)
	}
	router.mu.Lock()
	if router.mapped[Port{Proto: UDP, Port: 7882}] != 7882 || router.mapped[Port{Proto: TCP, Port: 7881}] != 7881 {
		t.Errorf("the router forwards %v", router.mapped)
	}
	router.mu.Unlock()
	cancel()
	<-done
	if _, unmapped := router.counts(); len(unmapped) != 3 {
		t.Fatalf("unmapped on stop: %v", unmapped)
	}

	// A router that maps no UDP: the TCP port is still mapped, and the UDP one is asked for again on renewing.
	noUDP := &fakeGateway{kind: "UPnP", ip: net.IPv4(203, 0, 113, 7), refused: UDP}
	m = NewMapper("ptt-server", serverPort, media)
	m.Find = func(context.Context) []Gateway { return []Gateway{noUDP} }
	run(t, m)
	waitFor(t, "the TCP mapping", func() bool { return m.Current() != nil })
	waitFor(t, "a renewal", func() bool { n, _ := noUDP.counts(); return n >= 2 })
	if m.Of(media) != nil {
		t.Fatalf("a UDP mapping the router refused: %+v", m.Of(media))
	}
}

// A port that must keep its number isn't moved to the next one when another machine holds it, and a router that
// grants another number (NAT-PMP may) isn't kept.
func TestAnExactPortKeepsItsNumber(t *testing.T) {
	shortTimes(t)
	media := Port{Proto: UDP, Port: 7882, Exact: true}
	taken := &fakeGateway{kind: "UPnP", ip: net.IPv4(203, 0, 113, 7), taken: map[Port]bool{{UDP, 7882, false}: true}}
	m := NewMapper("ptt-server", serverPort, media)
	m.Find = func(context.Context) []Gateway { return []Gateway{taken} }
	run(t, m)
	waitFor(t, "the TCP mapping", func() bool { return m.Current() != nil })
	if m.Of(media) != nil {
		t.Fatalf("UDP mapped to another port: %+v", m.Of(media))
	}

	other := &fakeGateway{kind: "NAT-PMP", ip: net.IPv4(203, 0, 113, 7), external: 40000}
	m2 := NewMapper("ptt-server", media)
	m2.Find = func(context.Context) []Gateway { return []Gateway{other} }
	run(t, m2)
	waitFor(t, "the router asked", func() bool { n, _ := other.counts(); return n >= 1 })
	time.Sleep(30 * time.Millisecond)
	if m2.Of(media) != nil {
		t.Fatalf("kept a mapping to another port: %+v", m2.Of(media))
	}
	if _, unmapped := other.counts(); len(unmapped) == 0 || unmapped[0] != (Port{UDP, 40000, false}) {
		t.Fatalf("the wrong port wasn't given back: %v", unmapped)
	}
}
