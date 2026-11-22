package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/discovery"
	"github.com/chencohensolutions/push-to-talk-server-go/graph/model"
	"github.com/chencohensolutions/push-to-talk-server-go/portmap"
)

// Finding the server whose address changes (docs/discovery.md). This server publishes where it is in the BitTorrent
// DHT, and tells its phones in the enrollment QR code and serverInfo.discovery; a phone looks it up in the DHT when
// none of the addresses it knows answers.

// serverDiscovery is this server's side: its id, its DHT key and the publisher of its addresses.
type serverDiscovery struct {
	fingerprint string
	key         ed25519.PrivateKey // nil with "discovery": false
	publisher   *discovery.Publisher
}

// dhtNode is this process's place in the DHT, shared by the publisher and the discovery command; it joins at first
// use.
var dhtNode = &discovery.Node{}

// openDiscovery reads this server's key for discovery. Without "discovery": false the publisher publishes in the DHT
// once run.
func openDiscovery(config auth.AppConfig) (*serverDiscovery, error) {
	pair, err := tls.LoadX509KeyPair(config.TLSCert, config.TLSKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	return newServerDiscovery(config, leaf, pair.PrivateKey)
}

func newServerDiscovery(config auth.AppConfig, leaf *x509.Certificate, key any) (*serverDiscovery, error) {
	d := &serverDiscovery{fingerprint: discovery.Fingerprint(leaf)}
	d.publisher = &discovery.Publisher{Fingerprint: d.fingerprint, PublicURL: config.PublicURL, Port: config.Port,
		STUN: discovery.STUNServers}
	if config.DiscoveryOn() {
		var err error
		if d.key, err = discovery.KeyFor(key); err != nil {
			return nil, err
		}
		d.publisher.Node, d.publisher.Key = dhtNode, d.key
	}
	return d, nil
}

// serverPorts is what the server asks the router to forward: its own TCP port, and with LiveKit its media ports
// (UDP 7882, TCP 7881) with the same numbers outside, since LiveKit tells the phones its own port numbers.
func serverPorts(config auth.AppConfig) ([]portmap.Port, error) {
	port, err := strconv.ParseUint(config.Port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("port %q: %w", config.Port, err)
	}
	ports := []portmap.Port{{Proto: portmap.TCP, Port: uint16(port)}}
	if config.LiveKitOn() {
		ports = append(ports, portmap.Port{Proto: portmap.UDP, Port: uint16(config.LiveKit.UDPPort), Exact: true},
			portmap.Port{Proto: portmap.TCP, Port: uint16(config.LiveKit.TCPPort), Exact: true})
	}
	return ports, nil
}

// mapPorts asks the router to forward the server's ports to this machine while it runs (package portmap), unless
// config.json sets "port_mapping": false, and gives the outside address to d's publisher. done is closed once the
// mappings are removed after running ends (at once when there are none).
func mapPorts(running context.Context, config auth.AppConfig, d *serverDiscovery, done chan<- struct{}) {
	ports, err := serverPorts(config)
	if !config.PortMappingOn() || err != nil {
		close(done)
		return
	}
	m := portmap.NewMapper("ptt-server", ports...)
	d.publisher.Mapped = func() string { return m.Current().URL() }
	go func() { m.Run(running); close(done) }()
}

// printRouters lists the routers that map ports and their outside addresses, for `ptt-server discovery`. It only
// asks: mapping the ports from here would take over the running server's mapping and remove it on exit.
func printRouters(ctx context.Context, config auth.AppConfig) {
	if !config.PortMappingOn() {
		fmt.Printf("Port mapping is off in config.json (\"port_mapping\": false)\n\n")
		return
	}
	ask, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	gws := portmap.Find(ask)
	if len(gws) == 0 {
		fmt.Printf("No router here maps ports (UPnP and NAT-PMP off, or none answers): forward TCP %s by hand, or use IPv6\n\n", config.Port)
		return
	}
	fmt.Printf("Routers that map ports (the running server asks them to forward TCP %s):\n", config.Port)
	for _, g := range gws {
		ip, err := g.ExternalIP(ask)
		switch {
		case err != nil:
			fmt.Printf("  %s: outside address unknown: %v\n", g.Kind(), err)
		case !portmap.Public(ip):
			fmt.Printf("  %s: outside address %s isn't public (carrier-grade NAT, or another router in front): the internet can't reach this server through it\n", g.Kind(), ip)
		default:
			fmt.Printf("  %s: outside address %s\n", g.Kind(), ip)
		}
	}
	fmt.Println()
}

// forPhones is serverInfo.discovery: who this server is and where.
func (d *serverDiscovery) forPhones() *model.ServerDiscovery {
	out := &model.ServerDiscovery{Fingerprint: d.fingerprint, ID: discovery.FormatID(d.fingerprint),
		Addresses: d.publisher.Current()}
	if d.key != nil {
		key := hex.EncodeToString(d.key.Public().(ed25519.PublicKey))
		out.Key = &key
	}
	if out.Addresses == nil {
		out.Addresses = []string{}
	}
	return out
}

// idCommand: ptt-server id. This server's id, as phones know it.
func idCommand(config auth.AppConfig) error {
	d, err := openDiscovery(config)
	if err != nil {
		return err
	}
	fmt.Printf("Server id:   %s\n", discovery.FormatID(d.fingerprint))
	fmt.Printf("Fingerprint: %s\n", d.fingerprint)
	if d.key != nil {
		fmt.Printf("DHT key:     %s\n", hex.EncodeToString(d.key.Public().(ed25519.PublicKey)))
	} else {
		fmt.Printf("DHT:         off (\"discovery\": false)\n")
	}
	return nil
}

// discoveryCommand: ptt-server discovery. Works out where this server is, publishes it in the DHT and looks it up
// again, to check discovery works from this network. The running server does the same by itself.
func discoveryCommand(config auth.AppConfig) error {
	d, err := openDiscovery(config)
	if err != nil {
		return err
	}
	if d.key == nil {
		return errors.New(`discovery is off in config.json ("discovery": false)`)
	}
	defer dhtNode.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	fmt.Printf("Server id %s\n\n", discovery.FormatID(d.fingerprint))
	printRouters(ctx, config)
	addresses := d.publisher.Addresses(ctx)
	fmt.Printf("This server's addresses:\n")
	for _, a := range addresses {
		fmt.Printf("  %s\n", a)
	}
	fmt.Printf("\nPublishing them in the DHT (joining it takes a few seconds)...\n")
	if err := dhtNode.Publish(ctx, d.key, d.fingerprint, discovery.Record{Addresses: addresses, At: time.Now().UTC()}); err != nil {
		fmt.Printf("  failed: %v\n", err)
	} else {
		fmt.Printf("  done\n")
	}
	if record, err := dhtNode.Lookup(ctx, d.key.Public().(ed25519.PublicKey), d.fingerprint); err != nil {
		fmt.Printf("  looking it up again: %v\n", err)
	} else {
		fmt.Printf("  found again: %s\n", strings.Join(record.Addresses, ", "))
	}
	return nil
}
