package main

import (
	"context"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"time"

	"go.uber.org/zap"
)

func main() {
	var (
		dnsResolverIP        = "127.0.0.1:5300" // DNS resolver
		dnsResolverProto     = "udp"            // Protocol to use for the DNS resolver
		dnsResolverTimeoutMs = 2000             // Timeout (ms) for the DNS resolver
		dialTimeoutMs        = 5000             // Timeout (ms) for the dial
	)

	l, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	logger := l.Sugar()

	dialer := &net.Dialer{
		Timeout: time.Duration(dialTimeoutMs) * time.Millisecond,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				dialer := net.Dialer{
					Timeout: time.Duration(dnsResolverTimeoutMs) * time.Millisecond,
				}
				return dialer.DialContext(ctx, dnsResolverProto, dnsResolverIP)
			},
		},
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	tr := http.DefaultTransport
	tr.(*http.Transport).DialContext = dialContext

	httpClient := &http.Client{
		Transport: tr,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://github.com/caelansar", nil)
	if err != nil {
		log.Fatalln(err)
	}

	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			logger.Debugw("[trace] Got Conn", "conn", connInfo)
		},
		ConnectDone: func(_, addr string, err error) {
			logger.Debugw("[trace] Conn done", "addr", addr, "err", err)
		},
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			logger.Debugw("[trace] DNS done", "dns", dnsInfo)
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		panic("invalid Status code")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Fatal(err)
	}

	logger.Debugw("get response body", "data", string(body))
}
