// Copyright 2026 Horizon Digital Engineering LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kmip

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// ClientOptions configures a KmipClient.
type ClientOptions struct {
	Host       string        // KMIP server hostname
	Port       int           // KMIP server port (default 5696)
	ClientCert string        // Path to client certificate PEM
	ClientKey  string        // Path to client private key PEM
	CACert     string        // Path to CA certificate PEM (optional)
	Timeout    time.Duration // Connection timeout (default 10s)
}

// KmipClient connects to a KMIP 1.4 server via mTLS.
type KmipClient struct {
	host    string
	port    int
	timeout time.Duration
	config  *tls.Config
	conn    *tls.Conn
}

// NewClient creates a new KmipClient.
func NewClient(opts ClientOptions) (*KmipClient, error) {
	if opts.Port == 0 {
		opts.Port = 5696
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	// Load client certificate and key
	cert, err := tls.LoadX509KeyPair(opts.ClientCert, opts.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("KMIP: failed to load client certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Load CA certificate if provided
	if opts.CACert != "" {
		caPEM, err := os.ReadFile(opts.CACert)
		if err != nil {
			return nil, fmt.Errorf("KMIP: failed to read CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("KMIP: failed to parse CA certificate")
		}
		tlsConfig.RootCAs = pool
	} else {
		tlsConfig.InsecureSkipVerify = true
	}

	return &KmipClient{
		host:    opts.Host,
		port:    opts.Port,
		timeout: opts.Timeout,
		config:  tlsConfig,
	}, nil
}

// Locate finds keys by name.
func (c *KmipClient) Locate(name string) ([]string, error) {
	request := BuildLocateRequest(name)
	responseData, err := c.send(request)
	if err != nil {
		return nil, err
	}
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}
	result := ParseLocatePayload(resp.Payload)
	return result.UniqueIdentifiers, nil
}

// Get fetches key material by unique ID.
func (c *KmipClient) Get(uniqueID string) (*GetResult, error) {
	request := BuildGetRequest(uniqueID)
	responseData, err := c.send(request)
	if err != nil {
		return nil, err
	}
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}
	return ParseGetPayload(resp.Payload), nil
}

// Create creates a new symmetric key on the server.
func (c *KmipClient) Create(name string, algorithm int, length int32) (*CreateResult, error) {
	if algorithm == 0 {
		algorithm = AlgorithmAES
	}
	if length == 0 {
		length = 256
	}
	request := BuildCreateRequest(name, algorithm, length)
	responseData, err := c.send(request)
	if err != nil {
		return nil, err
	}
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}
	return ParseCreatePayload(resp.Payload), nil
}

// FetchKey locates a key by name and returns the raw key bytes.
func (c *KmipClient) FetchKey(name string) ([]byte, error) {
	ids, err := c.Locate(name)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("KMIP: no key found with name %q", name)
	}
	result, err := c.Get(ids[0])
	if err != nil {
		return nil, err
	}
	if result.KeyMaterial == nil {
		return nil, fmt.Errorf("KMIP: key %q (%s) has no extractable material", name, ids[0])
	}
	return result.KeyMaterial, nil
}

// Close shuts down the TLS connection.
func (c *KmipClient) Close() error {
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

// send sends a KMIP request and receives the response.
func (c *KmipClient) send(request []byte) ([]byte, error) {
	conn, err := c.connect()
	if err != nil {
		return nil, err
	}

	// Write request
	if _, err := conn.Write(request); err != nil {
		return nil, fmt.Errorf("KMIP: failed to write request: %w", err)
	}

	// Read TTLV header (8 bytes) to determine response length
	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("KMIP: failed to read response header: %w", err)
	}

	valueLength := int(binary.BigEndian.Uint32(header[4:8]))
	response := make([]byte, 8+valueLength)
	copy(response, header)

	if _, err := io.ReadFull(conn, response[8:]); err != nil {
		return nil, fmt.Errorf("KMIP: failed to read response body: %w", err)
	}

	return response, nil
}

// connect establishes or reuses the mTLS connection.
func (c *KmipClient) connect() (*tls.Conn, error) {
	if c.conn != nil {
		return c.conn, nil
	}

	addr := fmt.Sprintf("%s:%d", c.host, c.port)
	dialer := &net.Dialer{Timeout: c.timeout}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, c.config)
	if err != nil {
		return nil, fmt.Errorf("KMIP connection failed: %w", err)
	}

	c.conn = conn
	return conn, nil
}

// ResolveAlgorithm converts an algorithm name string to its KMIP enum value.
func ResolveAlgorithm(name string) int {
	switch strings.ToUpper(name) {
	case "AES":
		return AlgorithmAES
	case "DES":
		return AlgorithmDES
	case "TRIPLEDES", "3DES":
		return AlgorithmTripleDES
	case "RSA":
		return AlgorithmRSA
	case "DSA":
		return AlgorithmDSA
	case "ECDSA":
		return AlgorithmECDSA
	case "HMACSHA1":
		return AlgorithmHMACSHA1
	case "HMACSHA256":
		return AlgorithmHMACSHA256
	case "HMACSHA384":
		return AlgorithmHMACSHA384
	case "HMACSHA512":
		return AlgorithmHMACSHA512
	default:
		return AlgorithmAES
	}
}
