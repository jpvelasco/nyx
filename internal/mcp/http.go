// HTTP transport for the MCP server (#138, docs/mcp-http.md): MCP
// streamable HTTP with session IDs, bound to loopback only and guarded
// by a bearer token. One Server value per session keeps initialize state
// isolated; the JSON-RPC method surface, result shapes, per-call timeout,
// and credential resolution are identical to stdio.
//
// Security model (the design doc is the contract):
//   - loopback bind only; non-loopback binds are refused with an
//     actionable message and there is no remote escape hatch;
//   - every request requires `Authorization: Bearer <token>` — the token
//     authenticates the listener, never the SDN controllers, and never
//     appears in URLs, logs, or tool output;
//   - the token is read from NYX_MCP_TOKEN or generated at process start
//     and printed once to stderr;
//   - comparison is constant-time; failures get a generic 401 body;
//   - no new secret-bearing HTTP fields exist: controller credentials
//     keep the stdio resolution chain (args → env → Credential Manager →
//     store) and are never accepted, stored, or multiplexed here.

package mcp

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// sessionIdleTimeout closes a streamable-HTTP session that has seen no
// request for this window; the next request on its session ID is a new
// session and must initialize again. Minutes, not hours, per the design.
const sessionIdleTimeout = 30 * time.Minute

// httpAuthError is the generic 401 body: no echoed material.
const httpAuthError = `{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"unauthorized"}}`

// httpSession is one MCP streamable-HTTP session: its own Server value
// with its own initialize state and trace namespace.
type httpSession struct {
	server   *Server
	lastUsed time.Time
}

// HTTPServer serves MCP streamable HTTP on a loopback listener.
type HTTPServer struct {
	token       string
	mu          sync.Mutex
	sessions    map[string]*httpSession
	idleTimeout time.Duration
}

// NewHTTPServer creates the listener surface guarded by token. The token
// is a listener credential (from NYX_MCP_TOKEN or generated at start).
func NewHTTPServer(token string) *HTTPServer {
	return &HTTPServer{
		token:       token,
		sessions:    map[string]*httpSession{},
		idleTimeout: sessionIdleTimeout,
	}
}

// GenerateListenerToken returns a random 32-byte hex token for the
// listener. It is a listener credential only — never an SDN controller
// secret, an API key, or a probe key.
func GenerateListenerToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating MCP listener token: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// ValidateBindAddr enforces the loopback-only binding rule: the address
// must resolve to a loopback interface. The error names the rule — there
// is no remote mode.
func ValidateBindAddr(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid bind address %q: %v (bind to loopback only; remote exposure is out of scope)", addr, err)
	}
	if port == "" {
		return "", fmt.Errorf("bind address %q needs a port (bind to loopback only; remote exposure is out of scope)", addr)
	}
	if host == "" {
		return "", fmt.Errorf("bind address %q has no host (bind to loopback only; remote exposure is out of scope)", addr)
	}
	// Resolve hostnames (e.g. localhost) and check every result is
	// loopback; a name that resolves to anything non-loopback is refused.
	var lastErr error
	for _, resolved := range resolveHost(host) {
		ip := net.ParseIP(resolved)
		if ip == nil {
			lastErr = fmt.Errorf("bind host %q does not resolve to an IP (bind to loopback only; remote exposure is out of scope)", host)
			continue
		}
		if ip.IsLoopback() {
			return net.JoinHostPort(resolved, port), nil
		}
		lastErr = fmt.Errorf("bind address %q is not loopback (bind to loopback only; remote exposure is out of scope)", addr)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("bind host %q does not resolve (bind to loopback only; remote exposure is out of scope)", host)
	}
	return "", lastErr
}

// resolveHost expands a bind host into candidate IPs: a bare IP parses
// directly; a name resolves via the resolver.
func resolveHost(host string) []string {
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		return nil
	}
	return ips
}

// Handler returns the http.Handler serving MCP streamable HTTP at /mcp.
func (h *HTTPServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", h.serveMCP)
	return mux
}

// serveMCP applies auth, session routing, and the JSON-RPC dispatch for
// one streamable-HTTP request.
func (h *HTTPServer) serveMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeHTTPJSONError(w, http.StatusMethodNotAllowed, "method not allowed: only POST is supported")
		return
	}
	if !h.authorized(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, httpAuthError) // best-effort generic body
		return
	}

	// One JSON-RPC message per POST body, capped like the stdio frame
	// limit so a single request cannot exhaust memory.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxFrameSize+1))
	if err != nil || len(body) > maxFrameSize {
		writeHTTPJSONError(w, http.StatusBadRequest, "request body exceeds the size limit")
		return
	}

	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeHTTPJSONError(w, http.StatusBadRequest, "parse error: invalid JSON-RPC message")
		return
	}

	// Notifications have no ID: accept them without a response body.
	if req.ID == nil || string(req.ID) == "null" {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	sessionID := r.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		if req.Method != "initialize" {
			writeHTTPJSONError(w, http.StatusBadRequest, "session required: initialize first (Mcp-Session-Id missing)")
			return
		}
		sessionID = h.newSession()
	} else {
		if req.Method == "initialize" {
			// Re-initializing on an existing session is a client protocol
			// error; the client must start a new session by omitting the ID.
			writeHTTPJSONError(w, http.StatusBadRequest, "session already initialized: omit Mcp-Session-Id to start a new session")
			return
		}
		if !h.touchSession(sessionID) {
			// Unknown or idle-expired session: the client must re-initialize.
			writeHTTPJSONError(w, http.StatusNotFound, "session not found: initialize again")
			return
		}
	}

	srv := h.sessionServer(sessionID)
	resp := srv.handleRequest(r.Context(), &req)
	respBytes, err := json.Marshal(resp)
	if err != nil {
		writeHTTPJSONError(w, http.StatusInternalServerError, "encoding response failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if req.Method == "initialize" {
		w.Header().Set("Mcp-Session-Id", sessionID)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes) // response write is best-effort
}

// authorized applies the constant-time bearer check. The token is never
// compared non-constant-time, echoed, or logged.
func (h *HTTPServer) authorized(r *http.Request) bool {
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	presented := header[len(prefix):]
	return subtle.ConstantTimeCompare([]byte(presented), []byte(h.token)) == 1
}

// newSession creates a session with a fresh unguessable ID and its own
// Server value. The Server's stdio reader/writer are never used over
// HTTP — only the pure request dispatch.
func (h *HTTPServer) newSession() string {
	var b [16]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			// A non-cryptographic fallback is never acceptable here: an
			// unguessable session ID is part of the security model.
			panic(fmt.Sprintf("generating MCP session ID: %v", err))
		}
		id := hex.EncodeToString(b[:])
		h.mu.Lock()
		if _, exists := h.sessions[id]; !exists {
			h.sessions[id] = &httpSession{server: NewServer(), lastUsed: time.Now()}
			h.mu.Unlock()
			return id
		}
		h.mu.Unlock()
	}
}

// touchSession reports whether sessionID is known and not idle-expired,
// refreshing its last-used time. Expired sessions are removed.
func (h *HTTPServer) touchSession(sessionID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.sessions[sessionID]
	if !ok {
		return false
	}
	if time.Since(s.lastUsed) > h.idleTimeout {
		delete(h.sessions, sessionID)
		return false
	}
	s.lastUsed = time.Now()
	return true
}

// sessionServer returns the Server for a session that was just verified
// by touchSession or created by newSession.
func (h *HTTPServer) sessionServer(sessionID string) *Server {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[sessionID].server
}

// SweepIdle removes sessions idle beyond the timeout. Exported for the
// periodic reaper and for tests.
func (h *HTTPServer) SweepIdle() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, s := range h.sessions {
		if time.Since(s.lastUsed) > h.idleTimeout {
			delete(h.sessions, id)
		}
	}
}

// StartReaper runs SweepIdle on a ticker until ctx is done.
func (h *HTTPServer) StartReaper(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(h.idleTimeout / 4)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.SweepIdle()
			}
		}
	}()
}

// writeHTTPJSONError renders a JSON-RPC-shaped error with a status code.
func writeHTTPJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		Error:   &rpcError{Code: -32000, Message: message},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_, _ = w.Write(data) // best-effort error body
}
