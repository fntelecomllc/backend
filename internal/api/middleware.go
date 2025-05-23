// File: backend/internal/api/middleware.go
package api

import (
	"log"
	"net/http"
	"strings"
	"time"
)

// LoggingMiddleware logs the incoming HTTP request
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// Wrap the original ResponseWriter to capture status code and support Flusher
		srw := NewStatusResponseWriter(w)

		log.Printf("Request Start: %s %s %s", r.Method, r.RequestURI, r.RemoteAddr)
		next.ServeHTTP(srw, r) // Pass the wrapped writer
		log.Printf("Request End: %s %s (Status: %d) %s (Duration: %s)", r.Method, r.RequestURI, srw.statusCode, r.RemoteAddr, time.Since(start))
	})
}

// StatusResponseWriter wraps ResponseWriter to capture status code
// and implements http.Flusher if the underlying writer supports it.
type StatusResponseWriter struct {
	http.ResponseWriter
	statusCode int
	flushed    bool // To track if headers have been written by Flush
}

// NewStatusResponseWriter creates a new StatusResponseWriter
func NewStatusResponseWriter(w http.ResponseWriter) *StatusResponseWriter {
	return &StatusResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
}

// WriteHeader captures the status code before writing headers
func (srw *StatusResponseWriter) WriteHeader(code int) {
	if !srw.flushed { // Only write headers if not already flushed (e.g., by SSE)
		srw.statusCode = code
		srw.ResponseWriter.WriteHeader(code)
	}
}

// Write captures the status code if WriteHeader hasn't been called (e.g. by http.Error)
// and then calls the underlying Write.
func (srw *StatusResponseWriter) Write(b []byte) (int, error) {
	if srw.statusCode == 0 && !srw.flushed { // If WriteHeader not called and not flushed
		// http.Error calls Write without WriteHeader, so default to 200 if not set.
		// Or, if it's an error path, a different status might have been implicitly set.
		// For SSE, WriteHeader is usually called explicitly with 200 first.
		// If Write is called before WriteHeader for a non-error SSE chunk, it's unusual.
		// We assume SSE calls WriteHeader(200) first.
	}
	return srw.ResponseWriter.Write(b)
}

// Flush implements the http.Flusher interface.
// It calls Flush on the underlying ResponseWriter if it supports it.
func (srw *StatusResponseWriter) Flush() {
	// If WriteHeader hasn't been called yet, set status to 200 for SSE.
	// SSE typically starts with a 200 OK and then streams.
	// The first Flush() call often happens after headers are set but before all data.
	if srw.statusCode == 0 && !srw.flushed { // If no status code set yet by an explicit WriteHeader
		// For SSE, the Content-Type header is text/event-stream.
		// If this is the first flush and headers haven't been written,
		// it's likely the SSE headers are being written now.
		// We don't set statusCode here as the SSE handler should call WriteHeader(200) itself.
	}
	
	if flusher, ok := srw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
		srw.flushed = true // Mark that flush has occurred
	} else {
		// log.Printf("Debug: Underlying ResponseWriter does not implement http.Flusher for LoggingMiddleware")
	}
}


// APIKeyAuthMiddleware (no changes needed to this middleware itself)
func APIKeyAuthMiddleware(apiKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions { next.ServeHTTP(w, r); return }
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" { http.Error(w, "Authorization header required", http.StatusUnauthorized); return }
			parts := strings.Split(authHeader, " "); if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" { http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized); return }
			if parts[1] != apiKey { log.Printf("Auth failed: Invalid API Key by %s for %s %s", r.RemoteAddr, r.Method, r.RequestURI); http.Error(w, "Invalid API Key", http.StatusUnauthorized); return }
			next.ServeHTTP(w, r)
		})
	}
}

// CORSMiddleware (no changes needed to this middleware itself)
func CORSMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*"); w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, PATCH")
        w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
        w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Date, X-Request-Id")
        if r.Method == "OPTIONS" { w.WriteHeader(http.StatusOK); return }
        next.ServeHTTP(w, r)
    })
}
