package ratelimit

// Redis-backed limiter/detector for multi-replica deployments: sliding
// windows must be shared across replicas or N replicas grant N times the
// limit. Implemented over a minimal hand-rolled RESP client (stdlib-first:
// the two commands we need do not justify a client-library dependency).
//
// Scheme: the same weighted two-bucket window as the in-memory limiter,
// with one Redis counter per (key, window-start) bucket:
//
//	INCR rl:{key}:{start}       EXPIRE rl:{key}:{start} 2*window
//	GET  rl:{key}:{start-1}     -> weighted sum decides
//
// Failure mode is configurable fail-open/fail-closed; the default is
// fail-open with a warning counter (rate limiting is abuse control - an
// unreachable Redis should degrade protection, not availability).

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// respConn is one pooled Redis connection.
type respConn struct {
	c  net.Conn
	rd *bufio.Reader
}

// RedisClient is a tiny connection-pooled RESP2 client (INCR/EXPIRE/GET/AUTH).
type RedisClient struct {
	Addr     string
	Password string

	mu   sync.Mutex
	idle []*respConn
}

func (r *RedisClient) get() (*respConn, error) {
	r.mu.Lock()
	if n := len(r.idle); n > 0 {
		conn := r.idle[n-1]
		r.idle = r.idle[:n-1]
		r.mu.Unlock()
		return conn, nil
	}
	r.mu.Unlock()
	c, err := net.DialTimeout("tcp", r.Addr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	conn := &respConn{c: c, rd: bufio.NewReader(c)}
	if r.Password != "" {
		if _, err := r.do(conn, "AUTH", r.Password); err != nil {
			_ = c.Close()
			return nil, err
		}
	}
	return conn, nil
}

func (r *RedisClient) put(conn *respConn) {
	r.mu.Lock()
	if len(r.idle) < 16 {
		r.idle = append(r.idle, conn)
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()
	_ = conn.c.Close()
}

// do writes one command and reads one reply. Replies map to: int64 for
// integers, string for bulk/simple strings, nil for null bulk.
func (r *RedisClient) do(conn *respConn, args ...string) (any, error) {
	_ = conn.c.SetDeadline(time.Now().Add(2 * time.Second))
	buf := fmt.Sprintf("*%d\r\n", len(args))
	for _, a := range args {
		buf += fmt.Sprintf("$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := conn.c.Write([]byte(buf)); err != nil {
		return nil, err
	}
	return readReply(conn.rd)
}

func readReply(rd *bufio.Reader) (any, error) {
	line, err := rd.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 3 {
		return nil, fmt.Errorf("redis: short reply")
	}
	body := line[1 : len(line)-2]
	switch line[0] {
	case '+':
		return body, nil
	case '-':
		return nil, fmt.Errorf("redis: %s", body)
	case ':':
		return strconv.ParseInt(body, 10, 64)
	case '$':
		n, err := strconv.Atoi(body)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil // null bulk
		}
		payload := make([]byte, n+2)
		if _, err := readFull(rd, payload); err != nil {
			return nil, err
		}
		return string(payload[:n]), nil
	default:
		return nil, fmt.Errorf("redis: unexpected reply type %q", line[0])
	}
}

func readFull(rd *bufio.Reader, p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := rd.Read(p[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// cmd runs one command on a pooled connection, discarding the connection on
// error (it may hold unread state).
func (r *RedisClient) cmd(args ...string) (any, error) {
	conn, err := r.get()
	if err != nil {
		return nil, err
	}
	out, err := r.do(conn, args...)
	if err != nil {
		_ = conn.c.Close()
		return nil, err
	}
	r.put(conn)
	return out, nil
}

// RedisLimiter is the shared-counter implementation of the lookup limiter
// and enumeration detector.
type RedisLimiter struct {
	Client *RedisClient
	// FailClosed blocks requests when Redis is unreachable. Default false:
	// degrade the abuse control, not availability - but count the failures.
	FailClosed bool
	// OnFailure, when set, is called on every Redis failure - wired to a
	// metrics counter by the server.
	OnFailure func()

	mu       sync.Mutex
	failures int64
	now      func() time.Time
}

func NewRedisLimiter(addr, password string, failClosed bool) *RedisLimiter {
	return &RedisLimiter{
		Client:     &RedisClient{Addr: addr, Password: password},
		FailClosed: failClosed,
		now:        time.Now,
	}
}

// Failures reports how many limiter decisions fell back due to Redis errors.
func (l *RedisLimiter) Failures() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.failures
}

func (l *RedisLimiter) failed() bool {
	l.mu.Lock()
	l.failures++
	l.mu.Unlock()
	if l.OnFailure != nil {
		// Ops visibility: fail-open degradation must not be silent
		// (review finding F4).
		l.OnFailure()
	}
	return !l.FailClosed
}

// windowCount increments the current bucket and returns the weighted total
// over (prefix, key) for the given span.
func (l *RedisLimiter) windowCount(prefix, key string, span time.Duration) (float64, error) {
	now := l.now()
	start := now.Truncate(span).Unix()
	prev := start - int64(span/time.Second)
	curKey := fmt.Sprintf("%s:%s:%d", prefix, key, start)
	prevKey := fmt.Sprintf("%s:%s:%d", prefix, key, prev)

	// One atomic script: INCR and EXPIRE together, so a crash between the
	// two can never leave an immortal counter key (review finding F4).
	cur, err := l.Client.cmd("EVAL",
		"local c = redis.call('INCR', KEYS[1]) if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end return c",
		"1", curKey, strconv.Itoa(int(2*span/time.Second)))
	if err != nil {
		return 0, err
	}
	prevVal := int64(0)
	if out, err := l.Client.cmd("GET", prevKey); err != nil {
		return 0, err
	} else if s, ok := out.(string); ok {
		prevVal, _ = strconv.ParseInt(s, 10, 64)
	}
	frac := 1 - float64(now.Sub(now.Truncate(span)))/float64(span)
	return float64(cur.(int64)) + frac*float64(prevVal), nil
}

// Allow implements the limiter interface (weighted sliding minute window).
func (l *RedisLimiter) Allow(key string, limit int) bool {
	if limit <= 0 {
		return false
	}
	total, err := l.windowCount("rl", key, window)
	if err != nil {
		return l.failed()
	}
	return total <= float64(limit)
}

// Miss implements the detector interface (sliding 10-minute window).
func (l *RedisLimiter) Miss(key string) int {
	total, err := l.windowCount("enum", key, detectWindow)
	if err != nil {
		_ = l.failed()
		return 0
	}
	return int(total)
}
