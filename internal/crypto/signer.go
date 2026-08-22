package crypto

// The signer IPC: a length-prefixed JSON protocol over a Unix domain
// socket, connecting the main process (RemoteEngine, no key material) to
// the signer process (ServeSigner, sole keystore holder). The protocol is
// deliberately tiny - six operations, no negotiation, no versioning
// beyond the "v" field - because every feature on this boundary is attack
// surface.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// maxFrame bounds a single request/response. PII blobs are small (attribute
// maps); 4 MiB leaves ample headroom while keeping a hostile peer from
// forcing large allocations.
const maxFrame = 4 << 20

type signerReq struct {
	V    int    `json:"v"`
	Op   string `json:"op"` // mac | seal | open | sign | verify | ensure
	Key  string `json:"key"`
	Alg  string `json:"alg,omitempty"`
	AAD  []byte `json:"aad,omitempty"`
	Data []byte `json:"data,omitempty"`
}

type signerResp struct {
	OK    bool   `json:"ok"`
	Out   []byte `json:"out,omitempty"`
	Error string `json:"error,omitempty"`
}

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > maxFrame {
		return fmt.Errorf("signer: frame too large (%d bytes)", len(b))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func readFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxFrame {
		return fmt.Errorf("signer: bad frame length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}

// ServeSigner runs the signer side over a Unix socket until ctx is
// cancelled. It is the ONLY code path that touches the keystore in split
// mode. The socket directory is created 0700 and the socket chmodded 0600:
// same-user processes only.
func ServeSigner(ctx context.Context, socketPath string, eng Engine) error {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return err
	}
	// A stale socket from a previous run blocks Listen; remove only if
	// nothing is accepting on it.
	if _, err := os.Stat(socketPath); err == nil {
		if c, err := net.DialTimeout("unix", socketPath, 200*time.Millisecond); err == nil {
			_ = c.Close()
			return fmt.Errorf("signer: %s is already being served", socketPath)
		}
		_ = os.Remove(socketPath)
	}
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer l.Close()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return err
	}
	// Track live connections so cancellation severs in-flight clients too -
	// a stopped signer must look exactly like a dead process to its callers.
	var cmu sync.Mutex
	conns := map[net.Conn]struct{}{}
	go func() {
		<-ctx.Done()
		_ = l.Close()
		cmu.Lock()
		for c := range conns {
			_ = c.Close()
		}
		cmu.Unlock()
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		cmu.Lock()
		conns[conn] = struct{}{}
		cmu.Unlock()
		go func() {
			serveConn(ctx, conn, eng)
			cmu.Lock()
			delete(conns, conn)
			cmu.Unlock()
		}()
	}
}

func serveConn(ctx context.Context, conn net.Conn, eng Engine) {
	defer conn.Close()
	for {
		var req signerReq
		if err := readFrame(conn, &req); err != nil {
			return // EOF or malformed frame: drop the connection
		}
		var out []byte
		var err error
		switch req.Op {
		case "mac":
			out, err = eng.MAC(ctx, req.Key, req.Data)
		case "seal":
			out, err = eng.Seal(ctx, req.Key, req.Alg, req.AAD, req.Data)
		case "open":
			out, err = eng.Open(ctx, req.Key, req.Alg, req.AAD, req.Data)
		case "sign":
			var tok string
			tok, err = eng.Sign(ctx, req.Key, req.Data)
			out = []byte(tok)
		case "verify":
			out, err = eng.VerifyToken(ctx, req.Key, string(req.Data))
		case "ensure":
			err = eng.Ensure(ctx, req.Key)
		default:
			err = fmt.Errorf("signer: unknown op %q", req.Op)
		}
		resp := signerResp{OK: err == nil, Out: out}
		if err != nil {
			resp.Error = err.Error()
		}
		if werr := writeFrame(conn, resp); werr != nil {
			return
		}
	}
}

// RemoteEngine implements Engine over the signer socket. The main process
// holds this instead of a keystore - key material never enters its address
// space.
type RemoteEngine struct {
	Socket string

	mu   sync.Mutex
	idle []net.Conn
}

func NewRemoteEngine(socket string) *RemoteEngine { return &RemoteEngine{Socket: socket} }

func (r *RemoteEngine) get() (net.Conn, error) {
	r.mu.Lock()
	if n := len(r.idle); n > 0 {
		c := r.idle[n-1]
		r.idle = r.idle[:n-1]
		r.mu.Unlock()
		return c, nil
	}
	r.mu.Unlock()
	return net.DialTimeout("unix", r.Socket, 2*time.Second)
}

func (r *RemoteEngine) put(c net.Conn) {
	r.mu.Lock()
	if len(r.idle) < 16 {
		r.idle = append(r.idle, c)
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()
	_ = c.Close()
}

func (r *RemoteEngine) call(ctx context.Context, req signerReq) ([]byte, error) {
	req.V = 1
	conn, err := r.get()
	if err != nil {
		return nil, fmt.Errorf("signer unreachable: %w", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	var resp signerResp
	if err := writeFrame(conn, req); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("signer write: %w", err)
	}
	if err := readFrame(conn, &resp); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("signer read: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	r.put(conn)
	if !resp.OK {
		return nil, errors.New(resp.Error)
	}
	return resp.Out, nil
}

func (r *RemoteEngine) MAC(ctx context.Context, key string, data []byte) ([]byte, error) {
	return r.call(ctx, signerReq{Op: "mac", Key: key, Data: data})
}
func (r *RemoteEngine) Seal(ctx context.Context, key, alg string, aad, plaintext []byte) ([]byte, error) {
	return r.call(ctx, signerReq{Op: "seal", Key: key, Alg: alg, AAD: aad, Data: plaintext})
}
func (r *RemoteEngine) Open(ctx context.Context, key, alg string, aad, blob []byte) ([]byte, error) {
	return r.call(ctx, signerReq{Op: "open", Key: key, Alg: alg, AAD: aad, Data: blob})
}
func (r *RemoteEngine) Sign(ctx context.Context, key string, payload []byte) (string, error) {
	out, err := r.call(ctx, signerReq{Op: "sign", Key: key, Data: payload})
	return string(out), err
}
func (r *RemoteEngine) VerifyToken(ctx context.Context, key, token string) ([]byte, error) {
	return r.call(ctx, signerReq{Op: "verify", Key: key, Data: []byte(token)})
}
func (r *RemoteEngine) Ensure(ctx context.Context, key string) error {
	_, err := r.call(ctx, signerReq{Op: "ensure", Key: key})
	return err
}
