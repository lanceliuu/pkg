/*
Copyright 2019 The Knative Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
)

// RoundTripperFunc implementation roundtrips a request.
type RoundTripperFunc func(*http.Request) (*http.Response, error)

// RoundTrip implements http.RoundTripper.
func (rt RoundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return rt(r)
}

func newAutoTransport(v1, v2 http.RoundTripper) http.RoundTripper {
	return RoundTripperFunc(func(r *http.Request) (*http.Response, error) {
		t := v1
		if r.ProtoMajor == 2 {
			t = v2
		}
		return t.RoundTrip(r)
	})
}

const sleepTO = 30 * time.Millisecond

var backOffTemplate = wait.Backoff{
	Duration: 50 * time.Millisecond,
	Factor:   1.4,
	Jitter:   0.1, // At most 10% jitter.
	Steps:    15,
}

// DialWithBackOff executes `net.Dialer.DialContext()` with exponentially increasing
// dial timeouts. In addition it sleeps with random jitter between tries.
var DialWithBackOff = NewBackoffDialer(backOffTemplate)

// NewBackoffDialer returns a dialer that executes `net.Dialer.DialContext()` with
// exponentially increasing dial timeouts. In addition it sleeps with random jitter
// between tries.
func NewBackoffDialer(backoffConfig wait.Backoff) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialBackOffHelper(ctx, network, address, backoffConfig, sleepTO)
	}
}

func dialBackOffHelper(ctx context.Context, network, address string, bo wait.Backoff, sleep time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   bo.Duration, // Initial duration.
		KeepAlive: 5 * time.Second,
		DualStack: true,
	}
	start := time.Now()
	for {
		c, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			var errNet net.Error
			if errors.As(err, &errNet) && errNet.Timeout() {
				if bo.Steps < 1 {
					break
				}
				dialer.Timeout = bo.Step()
				time.Sleep(wait.Jitter(sleep, 1.0)) // Sleep with jitter.
				continue
			}
			return nil, err
		}
		return c, nil
	}
	elapsed := time.Since(start)
	return nil, fmt.Errorf("timed out dialing after %.2fs", elapsed.Seconds())
}

func newHTTPTransport(disableKeepAlives bool, maxIdle, maxIdlePerHost int) http.RoundTripper {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = DialWithBackOff
	transport.DisableKeepAlives = disableKeepAlives
	transport.MaxIdleConns = maxIdle
	transport.MaxIdleConnsPerHost = maxIdlePerHost
	transport.ForceAttemptHTTP2 = false
	transport.TLSClientConfig = newmTLSClientConfig()
	return transport
}

func newmTLSClientConfig() *tls.Config {
	caFile := "/etc/istio-certs/root-cert.pem"
	certFile := "/etc/istio-certs/cert-chain.pem"
	keyFile := "/etc/istio-certs/key.pem"
	n := newmtlsCertificate(caFile, certFile, keyFile)
	return &tls.Config{
		RootCAs:              n.certPool,
		GetClientCertificate: n.getClientCertificate,
	}
}

type mtlsCertificate struct {
	caPath        string
	certPath      string
	keyPath       string
	certPool      *x509.CertPool
	clientKeyPair *tls.Certificate
	lock          sync.Mutex
}

func newmtlsCertificate(caPath, certPath, keyPath string) *mtlsCertificate {
	m := &mtlsCertificate{
		caPath:   caPath,
		certPath: certPath,
		keyPath:  keyPath,
	}
	m.init()
	return m
}

func (m *mtlsCertificate) init() {
	m.lock.Lock()
	defer m.lock.Unlock()
	clientCertPool := x509.NewCertPool()
	_, err := os.Stat(m.caPath)
	if err == nil {
		ca, _ := ioutil.ReadFile(m.caPath)
		clientCertPool.AppendCertsFromPEM(ca)
	}
	m.certPool = clientCertPool
	clientKeyPair, err := tls.LoadX509KeyPair(m.certPath, m.keyPath)
	if err == nil {
		m.clientKeyPair = &clientKeyPair
		go m.reloadClientKeyPair()
	}
}

func (m *mtlsCertificate) reloadClientKeyPair() {
	for {
		expireDate := m.clientKeyPair.Leaf.NotAfter
		fmt.Printf("cert expire date: %s", expireDate.String())
		timeToRefresh := expireDate.Sub(time.Now().Add(time.Duration(time.Minute * 5)))
		<-time.After(timeToRefresh)
		fmt.Printf("refresh cert at : %s", time.Now().String())
		clientKeyPair, err := tls.LoadX509KeyPair(m.certPath, m.keyPath)
		if err == nil {
			m.lock.Lock()
			defer m.lock.Unlock()
			m.clientKeyPair = &clientKeyPair
		}
	}
}

func (m *mtlsCertificate) getClientCertificate(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	// ignored cri
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.clientKeyPair, nil
}

// NewProberTransport creates a RoundTripper that is useful for probing,
// since it will not cache connections.
func NewProberTransport() http.RoundTripper {
	return newAutoTransport(
		newHTTPTransport(true /*disable keep-alives*/, 0, 0 /*no caching*/),
		NewH2CTransport())
}

// NewAutoTransport creates a RoundTripper that can use appropriate transport
// based on the request's HTTP version.
func NewAutoTransport(maxIdle, maxIdlePerHost int) http.RoundTripper {
	return newAutoTransport(
		newHTTPTransport(false /*disable keep-alives*/, maxIdle, maxIdlePerHost),
		NewH2CTransport())
}

// AutoTransport uses h2c for HTTP2 requests and falls back to `http.DefaultTransport` for all others
var AutoTransport = NewAutoTransport(1000, 100)
