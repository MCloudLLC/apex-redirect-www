// h2probe checks SNI/authority enforcement on an actual HTTP/2 TLS connection.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: h2probe LOOPBACK_HTTPS_ADDRESS")
	}
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			ServerName:         "example.com",
			InsecureSkipVerify: true, // Isolated Pebble CA; never used outside this test.
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, os.Args[1])
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	request, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		panic(err)
	}
	request.Host = "example.net"
	response, err := client.Do(request)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()
	if response.ProtoMajor != 2 || response.StatusCode != http.StatusMisdirectedRequest {
		panic(fmt.Sprintf("want HTTP/2 421; got %s %d", response.Proto, response.StatusCode))
	}
	fmt.Println("HTTP/2 SNI/authority mismatch denied with 421")
}
