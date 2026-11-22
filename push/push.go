// Package push wakes devices that have no open /ws through Firebase Cloud Messaging: a data-only message holding
// only the kind of wake-up, debounced per device, high priority only where it ends in a notification. See
// docs/messaging.md, "Push".
package push

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/enroll"
	"github.com/chencohensolutions/push-to-talk-server-go/store"
)

// Kind is the kind of wake-up an envelope is worth, from the least urgent to the most.
type Kind int

const (
	// None: no push (typing).
	None Kind = iota
	// Sync: something to fetch that shows nothing; normal priority, kept a day.
	Sync
	// Message: a message the user is notified of; high priority where notifications are on.
	Message
	// Talk (phase 5a) and Call (phase 5b): high priority where notifications are on, kept 30 seconds.
	Talk
	Call
)

func (k Kind) String() string {
	switch k {
	case Sync:
		return "sync"
	case Message:
		return "message"
	case Talk:
		return "talk"
	case Call:
		return "call"
	}
	return "none"
}

// wake is the FCM message of kind k for a device that does (or doesn't) show notifications.
func (k Kind) wake(notifications bool) Wake {
	switch k {
	case Message:
		return Wake{Kind: k.String(), High: notifications}
	case Talk, Call:
		return Wake{Kind: k.String(), High: notifications, TTL: 30 * time.Second}
	}
	return Wake{Kind: Sync.String(), TTL: 24 * time.Hour}
}

// Sender sends one FCM message (FCM, or a fake in tests).
type Sender interface {
	Send(ctx context.Context, token string, m Wake) error
}

const (
	// DefaultWindow is how long after a push to a device further envelopes wait for the next one.
	DefaultWindow = 3 * time.Second
	// attempts is how many times a push that failed with a RetryError is sent; retryAfter the wait after the first.
	attempts   = 3
	retryAfter = 2 * time.Second
)

// Pusher sends the pushes of one server. A nil Pusher, or one without a Sender, sends nothing.
type Pusher struct {
	Sender   Sender
	Registry *enroll.Registry
	// Connected says whether a device has /ws open now: it gets no push.
	Connected func(store.Device) bool
	// Window is the debounce (DefaultWindow); RetryAfter the wait before a second attempt (retryAfter).
	Window     time.Duration
	RetryAfter time.Duration
	Now        func() time.Time

	mu      sync.Mutex
	devices map[store.Device]*debounce
}

// debounce is one device's: when the last push went, and the most urgent kind waiting for the window to end.
type debounce struct {
	last    time.Time
	pending Kind
	timer   *time.Timer
}

// New is a pusher over sender (nil: no pushes) and the registry's tokens.
func New(sender Sender, registry *enroll.Registry, connected func(store.Device) bool) *Pusher {
	return &Pusher{Sender: sender, Registry: registry, Connected: connected, Window: DefaultWindow,
		RetryAfter: retryAfter, Now: time.Now, devices: map[store.Device]*debounce{}}
}

// On says whether the pusher sends anything.
func (p *Pusher) On() bool { return p != nil && p.Sender != nil }

// Queued says that an envelope worth kind was queued for d, which has no /ws open. The first push for a device goes
// at once; what comes within the window after it becomes one more push of the most urgent kind, at its end.
func (p *Pusher) Queued(d store.Device, kind Kind) {
	if !p.On() || kind == None {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.Now()
	state := p.devices[d]
	if state == nil {
		state = &debounce{}
		p.devices[d] = state
	}
	if state.timer == nil && (state.last.IsZero() || now.Sub(state.last) >= p.Window) {
		state.last = now
		go p.send(d, kind)
		return
	}
	state.pending = max(state.pending, kind)
	if state.timer == nil {
		state.timer = time.AfterFunc(state.last.Add(p.Window).Sub(now), func() { p.flush(d) })
	}
}

// flush sends what waited for the window's end, unless the device connected meanwhile.
func (p *Pusher) flush(d store.Device) {
	p.mu.Lock()
	state := p.devices[d]
	if state == nil { // forgotten meanwhile
		p.mu.Unlock()
		return
	}
	kind := state.pending
	state.pending, state.timer, state.last = None, nil, p.Now()
	p.mu.Unlock()
	if kind != None {
		p.send(d, kind)
	}
}

// Urgent pushes kind to d now, even when d has /ws open: a talk burst that a connected device didn't acknowledge
// within half a second (its connection may be dead without the server knowing yet).
func (p *Pusher) Urgent(d store.Device, kind Kind) {
	if !p.On() || kind == None {
		return
	}
	go p.push(d, kind)
}

// send pushes kind to d unless it has /ws open.
func (p *Pusher) send(d store.Device, kind Kind) {
	if p.Connected != nil && p.Connected(d) {
		return
	}
	p.push(d, kind)
}

// push sends kind to d's registered token, trying again after a passing failure, and drops a token FCM says is
// gone.
func (p *Pusher) push(d store.Device, kind Kind) {
	target, ok := p.Registry.PushTarget(d.User, d.Number, p.Now())
	if !ok {
		return
	}
	m := kind.wake(target.NotificationsEnabled)
	wait := p.RetryAfter
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := p.Sender.Send(ctx, target.FCMToken, m)
		cancel()
		switch {
		case err == nil:
			return
		case errors.Is(err, ErrUnregistered):
			if _, err := p.Registry.DropPushToken(target.FCMToken); err != nil {
				log.Printf("Push to device %d of %s: dropping its token: %v", d.Number, d.User, err)
			}
			log.Printf("Push to device %d of %s: its FCM token is gone, dropped", d.Number, d.User)
			return
		}
		var retry RetryError
		if !errors.As(err, &retry) || attempt == attempts {
			log.Printf("Push (%s) to device %d of %s: %v", m.Kind, d.Number, d.User, err)
			return
		}
		time.Sleep(wait)
		wait *= 2
	}
}

// AppUpdateTTL is how long FCM keeps an "app_update" push for a phone that is off.
const AppUpdateTTL = 7 * 24 * time.Hour

// AppUpdate tells every device with a push token that a new release of the app is out (package apprelease): a
// normal-priority "app_update" push, kept a week, sent to connected devices too (the app takes it while open as
// well). The phone then reads appRelease and offers the update. The pushes go one after another, in the background.
func (p *Pusher) AppUpdate() {
	if !p.On() {
		return
	}
	now := p.Now()
	seen := map[store.Device]bool{}
	var targets []enroll.Device
	for _, d := range p.Registry.List("") {
		key := store.Device{User: d.User, Number: d.DeviceNumber}
		if seen[key] {
			continue
		}
		seen[key] = true
		if target, ok := p.Registry.PushTarget(d.User, d.DeviceNumber, now); ok {
			targets = append(targets, target)
		}
	}
	m := Wake{Kind: "app_update", TTL: AppUpdateTTL}
	go func() {
		for _, t := range targets {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := p.Sender.Send(ctx, t.FCMToken, m)
			cancel()
			if errors.Is(err, ErrUnregistered) {
				if _, err := p.Registry.DropPushToken(t.FCMToken); err != nil {
					log.Printf("Push to device %d of %s: dropping its token: %v", t.DeviceNumber, t.User, err)
				}
			} else if err != nil {
				log.Printf("Push (app_update) to device %d of %s: %v", t.DeviceNumber, t.User, err)
			}
		}
		log.Printf("Push: told %d devices about the app update", len(targets))
	}()
}

// Forget drops what the pusher keeps for d (a revoked device).
func (p *Pusher) Forget(d store.Device) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if state := p.devices[d]; state != nil && state.timer != nil {
		state.timer.Stop()
	}
	delete(p.devices, d)
}
