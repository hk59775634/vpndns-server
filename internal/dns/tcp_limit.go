package dns

import (
	"context"
	"net"
	"sync"

	"golang.org/x/sync/semaphore"
)

type semListener struct {
	net.Listener
	sem *semaphore.Weighted
}

func newSemListener(inner net.Listener, max int64) net.Listener {
	if max <= 0 {
		return inner
	}
	return &semListener{Listener: inner, sem: semaphore.NewWeighted(max)}
}

func (l *semListener) Accept() (net.Conn, error) {
	if err := l.sem.Acquire(context.Background(), 1); err != nil {
		return nil, err
	}
	c, err := l.Listener.Accept()
	if err != nil {
		l.sem.Release(1)
		return nil, err
	}
	return &semConn{Conn: c, sem: l.sem}, nil
}

type semConn struct {
	net.Conn
	sem   *semaphore.Weighted
	close sync.Once
}

func (c *semConn) Close() error {
	var err error
	c.close.Do(func() {
		c.sem.Release(1)
		err = c.Conn.Close()
	})
	return err
}
