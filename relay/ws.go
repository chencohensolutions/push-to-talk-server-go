package relay

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	pb "github.com/chencohensolutions/push-to-talk-server-go/proto/pttv1"
	"github.com/chencohensolutions/push-to-talk-server-go/store"
	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"
)

// Close codes of /ws, beside the standard ones (docs/messaging.md).
const (
	// closeReplaced: the same device connected again; this, older, connection is closed.
	closeReplaced websocket.StatusCode = 4001
	// closeRevoked: the device was revoked or its user removed.
	closeRevoked websocket.StatusCode = 4003
)

const (
	// writeTimeout bounds one frame's write; a device that takes longer is gone.
	writeTimeout = 30 * time.Second
	// pingEvery is how often the server checks a quiet connection with a WebSocket ping, and pingTimeout how long
	// the pong may take.
	pingEvery   = 60 * time.Second
	pingTimeout = 30 * time.Second
	// queuePage is how many queued envelopes are read from the store at once.
	queuePage = 100
)

// conn is one device's /ws connection.
type conn struct {
	device store.Device
	serial string
	ws     *websocket.Conn
	// wake has a value when the device's queue may hold envelopes this connection hasn't sent.
	wake chan struct{}
	// live holds frames that aren't queued (talk, clip segments), written in order by liveWriter.
	live   chan []byte
	cancel context.CancelFunc
}

// liveQueue is how many live frames wait for one connection; past it, a slow device misses them.
const liveQueue = 512

// liveWriter writes c's live frames until the connection ends.
func liveWriter(ctx context.Context, c *conn) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-c.live:
			if c.write(ctx, data) != nil {
				return
			}
		}
	}
}

func (c *conn) close(code websocket.StatusCode, reason string) {
	go func() {
		c.ws.Close(code, reason)
		c.cancel()
	}()
}

// wake tells d's connection, if it has one, that its queue has more.
func (r *Relay) wake(d store.Device) {
	r.mu.Lock()
	c := r.conns[d]
	r.mu.Unlock()
	if c == nil {
		return
	}
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Connected says whether d has a /ws connection now.
func (r *Relay) Connected(d store.Device) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.conns[d] != nil
}

// ServeHTTP is /ws, behind identify (a certificate is required): the device's queue, then live envelopes, and its
// Sends and Acks. Frames are binary messages of one pb.Frame each.
func (r *Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	user := auth.FromContext(req.Context())
	device, _ := r.Registry.Find(auth.SerialFromContext(req.Context()))
	if user == nil || device.DeviceNumber == 0 {
		http.Error(w, "only an enrolled device can connect", http.StatusForbidden)
		return
	}
	ws, err := websocket.Accept(w, req, nil)
	if err != nil {
		log.Printf("/ws from %s.%d: %v", user.Name, device.DeviceNumber, err)
		return
	}
	ws.SetReadLimit(MaxFrameBytes)
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	c := &conn{device: store.Device{User: user.Name, Number: device.DeviceNumber}, serial: device.Serial, ws: ws,
		wake: make(chan struct{}, 1), live: make(chan []byte, liveQueue), cancel: cancel}
	r.mu.Lock()
	if old := r.conns[c.device]; old != nil {
		old.close(closeReplaced, "the device connected again")
	}
	r.conns[c.device] = c
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		if r.conns[c.device] == c {
			delete(r.conns, c.device)
		}
		r.mu.Unlock()
		r.disconnected(c.device.User)
		r.talkerGone(c.device)
		_ = r.Registry.Seen(c.serial, time.Now()) // it was here until now (Your devices' last seen)
	}()
	// Revoked between identify and here: don't stay.
	if r.Registry.IsRevoked(device.Serial) {
		ws.Close(closeRevoked, "revoked")
		return
	}
	r.connected(c.device.User)
	log.Printf("/ws: device %d of %s connected", c.device.Number, c.device.User)

	go r.deliver(ctx, c)
	go keepAlive(ctx, c)
	go liveWriter(ctx, c)
	err = r.read(ctx, c)
	if status := websocket.CloseStatus(err); status == -1 && !errors.Is(err, context.Canceled) {
		log.Printf("/ws: device %d of %s: %v", c.device.Number, c.device.User, err)
	}
	ws.CloseNow()
	log.Printf("/ws: device %d of %s disconnected", c.device.Number, c.device.User)
}

// write sends one frame.
func (c *conn) write(ctx context.Context, frame []byte) error {
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	err := c.ws.Write(ctx, websocket.MessageBinary, frame)
	if err != nil {
		c.cancel()
	}
	return err
}

func (c *conn) send(ctx context.Context, frame *pb.Frame) error {
	data, err := proto.Marshal(frame)
	if err != nil {
		return err
	}
	return c.write(ctx, data)
}

// deliver sends the device its queue, then QueueEmpty, then each envelope as it is queued. An envelope the device
// doesn't acknowledge stays queued and is sent again on its next connection.
func (r *Relay) deliver(ctx context.Context, c *conn) {
	var seq int64
	drained := false
	for {
		rows, err := r.Store.After(ctx, c.device, seq, queuePage)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("/ws: reading the queue of device %d of %s: %v", c.device.Number, c.device.User, err)
				c.cancel()
			}
			return
		}
		for _, row := range rows {
			if c.write(ctx, row.Envelope) != nil {
				return
			}
			seq = row.Seq
		}
		if len(rows) == queuePage {
			continue
		}
		if !drained {
			drained = true
			if c.send(ctx, &pb.Frame{Kind: &pb.Frame_QueueEmpty{QueueEmpty: &pb.QueueEmpty{}}}) != nil {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-c.wake:
		}
	}
}

// keepAlive pings the device now and then, and drops a connection that doesn't answer.
func keepAlive(ctx context.Context, c *conn) {
	ticker := time.NewTicker(pingEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
		err := c.ws.Ping(pingCtx)
		cancel()
		if err != nil {
			c.cancel()
			return
		}
	}
}

// read handles the device's frames until the connection ends.
func (r *Relay) read(ctx context.Context, c *conn) error {
	for {
		kind, data, err := c.ws.Read(ctx)
		if err != nil {
			return err
		}
		var frame pb.Frame
		if kind != websocket.MessageBinary || proto.Unmarshal(data, &frame) != nil {
			c.ws.Close(websocket.StatusUnsupportedData, "frames are binary ptt.v1.Frame")
			return nil
		}
		switch f := frame.Kind.(type) {
		case *pb.Frame_Send:
			result := r.Send(c.device, f.Send)
			if err := c.send(ctx, &pb.Frame{Kind: &pb.Frame_SendResult{SendResult: result}}); err != nil {
				return err
			}
		case *pb.Frame_Ack:
			if err := r.Store.Ack(c.device, f.Ack.GetIds()); err != nil {
				log.Printf("/ws: acknowledging for device %d of %s: %v", c.device.Number, c.device.User, err)
			}
		case *pb.Frame_Ping:
			if err := c.send(ctx, &pb.Frame{Kind: &pb.Frame_Pong{Pong: &pb.Pong{Id: f.Ping.GetId()}}}); err != nil {
				return err
			}
		case *pb.Frame_Pong:
		case *pb.Frame_TalkStart:
			if err := r.talkStart(ctx, c, f.TalkStart); err != nil {
				return err
			}
		case *pb.Frame_ClipSegment:
			if err := r.clipSegment(ctx, c, f.ClipSegment); err != nil {
				return err
			}
		case *pb.Frame_TalkEnd:
			r.talkEnd(c, f.TalkEnd)
		case *pb.Frame_TalkAck:
			r.talkAck(c, f.TalkAck)
		default:
			c.ws.Close(websocket.StatusPolicyViolation, "a device sends Send, Ack, Ping, Pong and the talk frames")
			return nil
		}
	}
}
