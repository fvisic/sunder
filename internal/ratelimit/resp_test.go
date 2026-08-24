package ratelimit

// Protocol-level tests for the minimal RESP client: a scripted TCP server
// feeds canned replies, so every reply type and error path runs without a
// real Redis.

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// scriptedRedis answers each received command with the next canned reply.
func scriptedRedis(t *testing.T, replies []string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	// Shared queue: replies survive connection drops (the client discards a
	// connection after an error reply and reconnects).
	queue := make(chan string, len(replies))
	for _, r := range replies {
		queue <- r
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				rd := bufio.NewReader(c)
				for {
					// Consume one RESP array command (n lines based on header).
					head, err := rd.ReadString('\n')
					if err != nil {
						return
					}
					if !strings.HasPrefix(head, "*") {
						return
					}
					n := 0
					_, _ = fmtSscanf(head, &n)
					for j := 0; j < n*2; j++ {
						if _, err := rd.ReadString('\n'); err != nil {
							return
						}
					}
					var reply string
					select {
					case reply = <-queue:
					default:
						return
					}
					if _, err := c.Write([]byte(reply)); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return l.Addr().String()
}

func fmtSscanf(head string, n *int) (int, error) {
	s := strings.TrimSpace(strings.TrimPrefix(head, "*"))
	v := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			break
		}
		v = v*10 + int(ch-'0')
	}
	*n = v
	return 1, nil
}

func TestRESPReplyTypes(t *testing.T) {
	addr := scriptedRedis(t, []string{
		":42\r\n",       // integer
		"+OK\r\n",       // simple string
		"$3\r\nabc\r\n", // bulk string
		"$-1\r\n",       // null bulk
		"-ERR boom\r\n", // error reply
		"*2\r\n",        // unexpected array type
	})
	c := &RedisClient{Addr: addr}
	if out, err := c.cmd("INCR", "k"); err != nil || out.(int64) != 42 {
		t.Fatalf("int reply: %v %v", out, err)
	}
	if out, err := c.cmd("SET", "k", "v"); err != nil || out.(string) != "OK" {
		t.Fatalf("simple reply: %v %v", out, err)
	}
	if out, err := c.cmd("GET", "k"); err != nil || out.(string) != "abc" {
		t.Fatalf("bulk reply: %v %v", out, err)
	}
	if out, err := c.cmd("GET", "missing"); err != nil || out != nil {
		t.Fatalf("null bulk: %v %v", out, err)
	}
	if _, err := c.cmd("GET", "k"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error reply: %v", err)
	}
	if _, err := c.cmd("GET", "k"); err == nil {
		t.Fatal("unexpected reply type must error")
	}
}

func TestRESPAuth(t *testing.T) {
	okAddr := scriptedRedis(t, []string{"+OK\r\n", ":1\r\n"})
	c := &RedisClient{Addr: okAddr, Password: "pw"}
	if out, err := c.cmd("INCR", "k"); err != nil || out.(int64) != 1 {
		t.Fatalf("auth then incr: %v %v", out, err)
	}
	badAddr := scriptedRedis(t, []string{"-ERR invalid password\r\n"})
	bad := &RedisClient{Addr: badAddr, Password: "wrong"}
	if _, err := bad.cmd("INCR", "k"); err == nil {
		t.Fatal("failed AUTH must surface")
	}
}

func TestRESPConnectionReuseAndFailure(t *testing.T) {
	addr := scriptedRedis(t, []string{":1\r\n", ":2\r\n"})
	c := &RedisClient{Addr: addr}
	if _, err := c.cmd("INCR", "a"); err != nil {
		t.Fatal(err)
	}
	// Second command must reuse the pooled connection (same scripted stream).
	if out, err := c.cmd("INCR", "a"); err != nil || out.(int64) != 2 {
		t.Fatalf("pooled reuse: %v %v", out, err)
	}
	dead := &RedisClient{Addr: "127.0.0.1:1"}
	if _, err := dead.cmd("PING"); err == nil {
		t.Fatal("unreachable server must error")
	}
}

func TestRedisWindowCountErrorPaths(t *testing.T) {
	// EXPIRE fails after INCR succeeds: windowCount must surface the error,
	// and both limiter and detector fall back per FailClosed.
	addr := scriptedRedis(t, []string{":1\r\n", "-ERR expire broke\r\n"})
	l := &RedisLimiter{Client: &RedisClient{Addr: addr}, FailClosed: true}
	l.now = timeNowFixed()
	if l.Allow("k", 5) {
		t.Fatal("fail-closed must block on mid-sequence redis error")
	}
	addr2 := scriptedRedis(t, []string{":1\r\n", "-ERR expire broke\r\n"})
	d := &RedisLimiter{Client: &RedisClient{Addr: addr2}}
	d.now = timeNowFixed()
	if got := d.Miss("k"); got != 0 {
		t.Fatalf("detector error path must return 0, got %d", got)
	}
}

func timeNowFixed() func() time.Time {
	fixed := time.Date(2026, 8, 22, 12, 0, 30, 0, time.UTC)
	return func() time.Time { return fixed }
}

func TestReadReplyVariants(t *testing.T) {
	read := func(s string) (any, error) {
		return readReply(bufio.NewReader(strings.NewReader(s)))
	}
	if v, err := read("+OK\r\n"); err != nil || v != "OK" {
		t.Fatalf("simple: %v %v", v, err)
	}
	if _, err := read("-ERR nope\r\n"); err == nil {
		t.Fatal("error reply must map to an error")
	}
	if v, err := read(":42\r\n"); err != nil || v.(int64) != 42 {
		t.Fatalf("int: %v %v", v, err)
	}
	if v, err := read("$3\r\nfoo\r\n"); err != nil || v != "foo" {
		t.Fatalf("bulk: %v %v", v, err)
	}
	if v, err := read("$-1\r\n"); err != nil || v != nil {
		t.Fatalf("null bulk: %v %v", v, err)
	}
	if _, err := read("$x\r\n"); err == nil {
		t.Fatal("bad bulk length must error")
	}
	if _, err := read("$5\r\nab"); err == nil {
		t.Fatal("truncated bulk must error")
	}
	if _, err := read("?huh\r\n"); err == nil {
		t.Fatal("unknown type must error")
	}
	if _, err := read("x\n"); err == nil {
		t.Fatal("short reply must error")
	}
	if _, err := read(""); err == nil {
		t.Fatal("EOF must error")
	}
}

func TestPutClosesWhenPoolFull(t *testing.T) {
	r := &RedisClient{}
	for i := 0; i < 17; i++ {
		c1, c2 := net.Pipe()
		_ = c2.Close()
		r.put(&respConn{c: c1, rd: bufio.NewReader(c1)})
	}
	if len(r.idle) != 16 {
		t.Fatalf("idle pool must cap at 16, got %d", len(r.idle))
	}
}

func TestRedisLimiterErrorReplies(t *testing.T) {
	l := NewRedisLimiter("", "", false)
	if l.Allow("k", 0) {
		t.Fatal("limit 0 must always deny")
	}
	// EVAL ok (atomic INCR+EXPIRE), GET errors: windowCount must surface the
	// error and the limiter fail-open.
	addr := scriptedRedis(t, []string{":1\r\n", "-ERR broken\r\n"})
	l2 := NewRedisLimiter(addr, "", false)
	if !l2.Allow("k", 10) {
		t.Fatal("fail-open limiter must allow on redis errors")
	}
	// Same but fail-closed.
	addr2 := scriptedRedis(t, []string{":1\r\n", "-ERR broken\r\n"})
	l3 := NewRedisLimiter(addr2, "", true)
	if l3.Allow("k", 10) {
		t.Fatal("fail-closed limiter must deny on redis errors")
	}
}
