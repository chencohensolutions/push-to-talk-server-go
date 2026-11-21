package discovery

import (
	"context"
	"crypto/ed25519"
	"log"
	"slices"
	"sync"
	"time"
)

// Publisher keeps this server's record in the DHT: at start, every RepublishEvery (nodes forget a record after
// about two hours), and within CheckEvery of its addresses changing. Without a Node (discovery off) it only keeps
// Current up to date, for serverInfo.discovery.
type Publisher struct {
	Node        *Node
	Key         ed25519.PrivateKey
	Fingerprint string
	PublicURL   string
	Port        string
	// Asked for the public IPv4 address; nil asks no one (tests).
	STUN []string
	// The router's outside address forwarded to this server ("https://ip:port"), or ""; nil when the server doesn't
	// map its port (portmap.Mapper).
	Mapped func() string

	mu      sync.Mutex
	current []string // Addresses when last worked out
	last    Record
}

var (
	RepublishEvery = 45 * time.Minute
	CheckEvery     = 5 * time.Minute
)

// Addresses is where this server can be reached now (Own).
func (p *Publisher) Addresses(ctx context.Context) []string {
	ip, err := PublicIPv4(ctx, p.STUN)
	if err != nil {
		ip = nil
	}
	return Own(p.PublicURL, p.mapped(), p.Port, ip)
}

func (p *Publisher) mapped() string {
	if p.Mapped == nil {
		return ""
	}
	return p.Mapped()
}

// Current is where this server can be reached, as last worked out (without asking STUN before the first time).
func (p *Publisher) Current() []string {
	p.mu.Lock()
	current := p.current
	p.mu.Unlock()
	if current == nil {
		return Own(p.PublicURL, p.mapped(), p.Port, nil)
	}
	return current
}

// Last is the record last published, with no addresses before the first.
func (p *Publisher) Last() Record {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.last
}

// Run publishes until ctx ends.
func (p *Publisher) Run(ctx context.Context) {
	var publishedAt time.Time
	failures := 0
	for {
		ask, cancel := context.WithTimeout(ctx, 10*time.Second)
		addresses := p.Addresses(ask)
		cancel()
		p.mu.Lock()
		changed := !slices.Equal(addresses, p.last.Addresses)
		p.current = addresses
		p.mu.Unlock()
		if p.Node != nil && (changed || time.Since(publishedAt) >= RepublishEvery) {
			r := Record{Addresses: addresses, At: time.Now().UTC()}
			put, cancel := context.WithTimeout(ctx, 2*time.Minute)
			err := p.Node.Publish(put, p.Key, p.Fingerprint, r)
			cancel()
			switch {
			case err == nil:
				if changed || failures > 0 {
					log.Printf("Discovery: published this server's addresses in the DHT: %v", addresses)
				}
				p.mu.Lock()
				p.last = r
				p.mu.Unlock()
				publishedAt, failures = time.Now(), 0
			case ctx.Err() == nil:
				if failures++; failures == 1 || failures%12 == 0 {
					log.Printf("Discovery: publishing in the DHT: %v (tried again every %s)", err, CheckEvery)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(CheckEvery):
		}
	}
}
