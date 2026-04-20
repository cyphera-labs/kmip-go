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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Maximum KMIP response size (16MB).
const maxResponseSize = 16 << 20

// ClientOptions configures a KmipClient.
// fixes MEDIUM-M1: InsecureSkipVerify removed from public struct.
type ClientOptions struct {
	Host       string        // KMIP server hostname (required)
	Port       int           // KMIP server port (default 5696)
	ClientCert string        // Path to client certificate PEM (required)
	ClientKey  string        // Path to client private key PEM (required)
	CACert     string        // Path to CA certificate PEM (uses system roots if empty)
	Timeout    time.Duration // Connection timeout (default 10s)
	// fixes MEDIUM-M3: KMIP Authentication credential support.
	Username string // KMIP username for UsernameAndPassword credential (optional)
	Password string // KMIP password for UsernameAndPassword credential (optional)
}

// KeyHandle wraps raw key material with secure zeroing on Close.
// fixes MEDIUM-M2: key material returned as bare []byte.
type KeyHandle struct {
	data []byte
}

// newKeyHandle creates a KeyHandle with a runtime finalizer as backstop.
func newKeyHandle(data []byte) *KeyHandle {
	h := &KeyHandle{data: data}
	runtime.SetFinalizer(h, func(kh *KeyHandle) { kh.Close() })
	return h
}

// Bytes returns the raw key bytes. Returns nil after Close.
func (h *KeyHandle) Bytes() []byte {
	return h.data
}

// Close zeroes the key material and releases it.
func (h *KeyHandle) Close() {
	if h.data != nil {
		for i := range h.data {
			h.data[i] = 0
		}
		runtime.KeepAlive(h.data)
		h.data = nil
		runtime.SetFinalizer(h, nil)
	}
}

// KmipClient connects to a KMIP 1.4 server via mTLS.
type KmipClient struct {
	mu       sync.Mutex
	host     string
	port     int
	timeout  time.Duration
	config   *tls.Config
	conn     *tls.Conn
	username string // fixes MEDIUM-M3
	password string // fixes MEDIUM-M3
}

// NewClient creates a new KmipClient.
func NewClient(opts ClientOptions) (*KmipClient, error) {
	if opts.Host == "" {
		return nil, fmt.Errorf("KMIP: host is required")
	}
	if opts.Port == 0 {
		opts.Port = 5696
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	// Load client certificate and key.
	if opts.ClientCert == "" || opts.ClientKey == "" {
		return nil, fmt.Errorf("KMIP: client certificate and key are required")
	}
	cert, err := tls.LoadX509KeyPair(opts.ClientCert, opts.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("KMIP: failed to load client certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}

	// Load CA certificate. If not provided, use system root CAs.
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
	}
	// When CACert is empty, RootCAs is nil → Go uses system certificate pool.

	return &KmipClient{
		host:     opts.Host,
		port:     opts.Port,
		timeout:  opts.Timeout,
		config:   tlsConfig,
		username: opts.Username,
		password: opts.Password,
	}, nil
}

// NewClientInsecure creates a KmipClient with server certificate verification disabled.
// This MUST only be used in test environments.
// fixes MEDIUM-M1: insecure mode gated behind a separate constructor.
func NewClientInsecure(opts ClientOptions) (*KmipClient, error) {
	fmt.Fprintln(os.Stderr, "WARNING: kmip-go: InsecureSkipVerify enabled — server certificate verification disabled")
	client, err := NewClient(opts)
	if err != nil {
		return nil, err
	}
	client.config.InsecureSkipVerify = true
	return client, nil
}

// Locate finds keys by name.
// fixes MEDIUM-M4: context propagation.
func (c *KmipClient) Locate(ctx context.Context, name string) ([]string, error) {
	request := BuildLocateRequest(name)
	responseData, err := c.send(ctx, request)
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
func (c *KmipClient) Get(ctx context.Context, uniqueID string) (*GetResult, error) {
	request := BuildGetRequest(uniqueID)
	responseData, err := c.send(ctx, request)
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
func (c *KmipClient) Create(ctx context.Context, name string, algorithm int, length int32) (*CreateResult, error) {
	if algorithm == 0 {
		algorithm = AlgorithmAES
	}
	if length == 0 {
		length = 256
	}
	request := BuildCreateRequest(name, algorithm, length)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return nil, err
	}
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}
	return ParseCreatePayload(resp.Payload), nil
}

// Activate sets a key's state to Active.
func (c *KmipClient) Activate(ctx context.Context, uniqueID string) error {
	request := BuildActivateRequest(uniqueID)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return err
	}
	_, err = ParseResponse(responseData)
	return err
}

// Destroy destroys a key by unique ID.
func (c *KmipClient) Destroy(ctx context.Context, uniqueID string) error {
	request := BuildDestroyRequest(uniqueID)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return err
	}
	_, err = ParseResponse(responseData)
	return err
}

// FetchKey locates a key by name and returns a KeyHandle wrapping the raw key bytes.
// fixes MEDIUM-M2: returns KeyHandle instead of bare []byte.
// fixes LOW-L3: errors when multiple keys match the name.
func (c *KmipClient) FetchKey(ctx context.Context, name string) (*KeyHandle, error) {
	ids, err := c.Locate(ctx, name)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("KMIP: no key found with name %q", name)
	}
	if len(ids) > 1 {
		// fixes LOW-L3: error when multiple keys match
		return nil, fmt.Errorf("KMIP: ambiguous — %d keys found with name %q", len(ids), name)
	}
	result, err := c.Get(ctx, ids[0])
	if err != nil {
		return nil, err
	}
	if result.KeyMaterial == nil {
		return nil, fmt.Errorf("KMIP: key %q (%s) has no extractable material", name, ids[0])
	}
	return newKeyHandle(result.KeyMaterial), nil
}

// CreateKeyPair creates a new asymmetric key pair on the server.
func (c *KmipClient) CreateKeyPair(ctx context.Context, name string, algorithm int, length int32) (*CreateKeyPairResult, error) {
	request := BuildCreateKeyPairRequest(name, algorithm, length)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return nil, err
	}
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}
	return ParseCreateKeyPairPayload(resp.Payload), nil
}

// Register registers existing key material on the server.
func (c *KmipClient) Register(ctx context.Context, objectType int, material []byte, name string, algorithm int, length int32) (*CreateResult, error) {
	request := BuildRegisterRequest(objectType, material, name, algorithm, length)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return nil, err
	}
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}
	return ParseCreatePayload(resp.Payload), nil
}

// ReKey re-keys an existing key on the server.
func (c *KmipClient) ReKey(ctx context.Context, uniqueID string) (*ReKeyResult, error) {
	request := BuildReKeyRequest(uniqueID)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return nil, err
	}
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}
	return ParseReKeyPayload(resp.Payload), nil
}

// DeriveKey derives a new key from an existing key.
func (c *KmipClient) DeriveKey(ctx context.Context, uniqueID string, derivationData []byte, name string, length int32) (*DeriveKeyResult, error) {
	request := BuildDeriveKeyRequest(uniqueID, derivationData, name, length)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return nil, err
	}
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}
	return ParseDeriveKeyPayload(resp.Payload), nil
}

// Check checks the status of a managed object.
func (c *KmipClient) Check(ctx context.Context, uniqueID string) (*CheckResult, error) {
	request := BuildCheckRequest(uniqueID)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return nil, err
	}
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}
	return ParseCheckPayload(resp.Payload), nil
}

// GetAttributes fetches all attributes of a managed object.
func (c *KmipClient) GetAttributes(ctx context.Context, uniqueID string) (*GetResult, error) {
	request := BuildGetAttributesRequest(uniqueID)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return nil, err
	}
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}
	return ParseGetPayload(resp.Payload), nil
}

// GetAttributeList fetches the list of attribute names for a managed object.
func (c *KmipClient) GetAttributeList(ctx context.Context, uniqueID string) ([]string, error) {
	request := BuildGetAttributeListRequest(uniqueID)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return nil, err
	}
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}
	if resp.Payload == nil {
		return nil, nil
	}
	attrs := FindChildren(resp.Payload, TagAttributeName)
	names := make([]string, 0, len(attrs))
	for _, attr := range attrs {
		names = append(names, attr.StringValue())
	}
	return names, nil
}

// AddAttribute adds an attribute to a managed object.
func (c *KmipClient) AddAttribute(ctx context.Context, uniqueID, name, value string) error {
	request := BuildAddAttributeRequest(uniqueID, name, value)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return err
	}
	_, err = ParseResponse(responseData)
	return err
}

// ModifyAttribute modifies an attribute of a managed object.
func (c *KmipClient) ModifyAttribute(ctx context.Context, uniqueID, name, value string) error {
	request := BuildModifyAttributeRequest(uniqueID, name, value)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return err
	}
	_, err = ParseResponse(responseData)
	return err
}

// DeleteAttribute deletes an attribute from a managed object.
func (c *KmipClient) DeleteAttribute(ctx context.Context, uniqueID, name string) error {
	request := BuildDeleteAttributeRequest(uniqueID, name)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return err
	}
	_, err = ParseResponse(responseData)
	return err
}

// ObtainLease obtains a lease for a managed object. Returns lease time in seconds.
func (c *KmipClient) ObtainLease(ctx context.Context, uniqueID string) (int, error) {
	request := BuildObtainLeaseRequest(uniqueID)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return 0, err
	}
	resp, err := ParseResponse(responseData)
	if err != nil {
		return 0, err
	}
	if resp.Payload == nil {
		return 0, nil
	}
	lease := FindChild(resp.Payload, TagLeaseTime)
	if lease != nil {
		return int(lease.IntValue()), nil
	}
	return 0, nil
}

// Revoke revokes a managed object with the given reason code.
func (c *KmipClient) Revoke(ctx context.Context, uniqueID string, reason int) error {
	request := BuildRevokeRequest(uniqueID, reason)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return err
	}
	_, err = ParseResponse(responseData)
	return err
}

// Archive archives a managed object.
func (c *KmipClient) Archive(ctx context.Context, uniqueID string) error {
	request := BuildArchiveRequest(uniqueID)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return err
	}
	_, err = ParseResponse(responseData)
	return err
}

// Recover recovers an archived managed object.
func (c *KmipClient) Recover(ctx context.Context, uniqueID string) error {
	request := BuildRecoverRequest(uniqueID)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return err
	}
	_, err = ParseResponse(responseData)
	return err
}

// Query queries the server for supported operations and object types.
func (c *KmipClient) Query(ctx context.Context) (*QueryResult, error) {
	request := BuildQueryRequest()
	responseData, err := c.send(ctx, request)
	if err != nil {
		return nil, err
	}
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}
	return ParseQueryPayload(resp.Payload), nil
}

// Poll polls the server.
func (c *KmipClient) Poll(ctx context.Context) error {
	request := BuildPollRequest()
	responseData, err := c.send(ctx, request)
	if err != nil {
		return err
	}
	_, err = ParseResponse(responseData)
	return err
}

// DiscoverVersions discovers the KMIP versions supported by the server.
func (c *KmipClient) DiscoverVersions(ctx context.Context) (*DiscoverVersionsResult, error) {
	request := BuildDiscoverVersionsRequest()
	responseData, err := c.send(ctx, request)
	if err != nil {
		return nil, err
	}
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}
	return ParseDiscoverVersionsPayload(resp.Payload), nil
}

// Encrypt encrypts data using a managed key.
func (c *KmipClient) Encrypt(ctx context.Context, uniqueID string, data []byte) (*EncryptResult, error) {
	request := BuildEncryptRequest(uniqueID, data)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return nil, err
	}
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}
	return ParseEncryptPayload(resp.Payload), nil
}

// Decrypt decrypts data using a managed key.
func (c *KmipClient) Decrypt(ctx context.Context, uniqueID string, data []byte, nonce []byte) (*DecryptResult, error) {
	request := BuildDecryptRequest(uniqueID, data, nonce)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return nil, err
	}
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}
	return ParseDecryptPayload(resp.Payload), nil
}

// Sign signs data using a managed key.
func (c *KmipClient) Sign(ctx context.Context, uniqueID string, data []byte) (*SignResult, error) {
	request := BuildSignRequest(uniqueID, data)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return nil, err
	}
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}
	return ParseSignPayload(resp.Payload), nil
}

// SignatureVerify verifies a signature using a managed key.
func (c *KmipClient) SignatureVerify(ctx context.Context, uniqueID string, data []byte, signature []byte) (*SignatureVerifyResult, error) {
	request := BuildSignatureVerifyRequest(uniqueID, data, signature)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return nil, err
	}
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}
	return ParseSignatureVerifyPayload(resp.Payload), nil
}

// MAC computes a MAC using a managed key.
func (c *KmipClient) MAC(ctx context.Context, uniqueID string, data []byte) (*MACResult, error) {
	request := BuildMACRequest(uniqueID, data)
	responseData, err := c.send(ctx, request)
	if err != nil {
		return nil, err
	}
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}
	return ParseMACPayload(resp.Payload), nil
}

// Close shuts down the TLS connection.
func (c *KmipClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

// ZeroBytes securely zeroes a byte slice. Call this on key material when done.
// The runtime.KeepAlive prevents the compiler from optimizing away the zeroing.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// send sends a KMIP request and receives the response.
// Thread-safe: only one operation at a time per connection.
// fixes MEDIUM-M4: accepts context for per-call deadlines.
func (c *KmipClient) send(ctx context.Context, request []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}

	// fixes MEDIUM-M4: use context deadline if set, otherwise fall back to timeout.
	deadline := time.Now().Add(c.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	conn.SetDeadline(deadline)

	// Write request.
	if _, err := conn.Write(request); err != nil {
		// fixes LOW-L4: close stale connection before nil assignment.
		c.conn.Close()
		c.conn = nil
		return nil, fmt.Errorf("KMIP: failed to write request: %w", err)
	}

	// Read TTLV header (8 bytes) to determine response length.
	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		// fixes LOW-L4: close stale connection before nil assignment.
		c.conn.Close()
		c.conn = nil
		return nil, fmt.Errorf("KMIP: failed to read response header: %w", err)
	}

	// Validate response size.
	valueLength := int(binary.BigEndian.Uint32(header[4:8]))
	if valueLength > maxResponseSize {
		// fixes LOW-L4: close stale connection before nil assignment.
		c.conn.Close()
		c.conn = nil
		return nil, fmt.Errorf("KMIP: response too large (%d bytes, max %d)", valueLength, maxResponseSize)
	}

	response := make([]byte, 8+valueLength)
	copy(response, header)

	if _, err := io.ReadFull(conn, response[8:]); err != nil {
		// fixes LOW-L4: close stale connection before nil assignment.
		c.conn.Close()
		c.conn = nil
		return nil, fmt.Errorf("KMIP: failed to read response body: %w", err)
	}

	// Clear deadline.
	conn.SetDeadline(time.Time{})

	return response, nil
}

// connect establishes or reuses the mTLS connection.
// fixes MEDIUM-M4: accepts context for dialer.
func (c *KmipClient) connect(ctx context.Context) (*tls.Conn, error) {
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
// Returns 0 for unknown algorithms.
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
		return 0
	}
}
