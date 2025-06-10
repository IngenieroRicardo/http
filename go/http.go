package http

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HttpRequest representa una petición HTTP
type HttpRequest struct {
	Method      string
	Path        string
	Body        string
	ClientIP    string
	Headers     string
	Username    string
	Password    string
	BearerToken string
}

// HttpResponse representa una respuesta HTTP
type HttpResponse struct {
	StatusCode int
	Body       string
}

// HttpHandler es el tipo para manejadores de peticiones HTTP
type HttpHandler func(req *HttpRequest) *HttpResponse

// ListManager gestiona las listas de IPs
type ListManager struct {
	whitelist map[string]bool
	blacklist map[string]bool
	mu        sync.RWMutex
}

// TokenManager gestiona tokens de autenticación
type TokenManager struct {
	tokens      map[string]time.Time
	secretKey   string
	mu          sync.RWMutex
	tokenExpiry time.Duration
}

// Server representa el servidor HTTP
type Server struct {
	ipListManager *ListManager
	tokenManager  *TokenManager
	enableFilter  bool
	certFile      string
	keyFile       string
}

// NewServer crea una nueva instancia del servidor
func NewServer() *Server {
	return &Server{
		ipListManager: &ListManager{
			whitelist: make(map[string]bool),
			blacklist: make(map[string]bool),
		},
		tokenManager: &TokenManager{
			tokens:      make(map[string]time.Time),
			secretKey:   "default-secret-key",
			tokenExpiry: 24 * time.Hour,
		},
	}
}

// parseBasicAuth extrae username y password del header Authorization
func parseBasicAuth(authHeader string) (username, password string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", "", false
	}
	c, err := base64.StdEncoding.DecodeString(authHeader[len(prefix):])
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return "", "", false
	}
	return cs[:s], cs[s+1:], true
}

// parseBearerToken extrae token Bearer del header Authorization
func parseBearerToken(authHeader string) (token string, ok bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", false
	}
	return authHeader[len(prefix):], true
}

// getClientIP obtiene la IP real del cliente
func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		ip := strings.TrimSpace(ips[0])
		if ip != "" {
			return ip
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	if ra := r.RemoteAddr; ra != "" {
		ip, _, err := net.SplitHostPort(ra)
		if err == nil {
			return ip
		}
		return ra
	}

	return ""
}

// GetHeaderValue gets a header value by name from the Headers string
func (req *HttpRequest) GetHeaderValue(name string) string {
	headers := strings.Split(req.Headers, "\n")
	for _, header := range headers {
		if strings.HasPrefix(header, name+":") {
			return strings.TrimSpace(strings.TrimPrefix(header, name+":"))
		}
	}
	return ""
}

// getHeadersString convierte los headers a string
func getHeadersString(r *http.Request) string {
	var sb strings.Builder
	for name, values := range r.Header {
		for _, value := range values {
			sb.WriteString(name)
			sb.WriteString(": ")
			sb.WriteString(value)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// sendErrorResponse envía una respuesta de error
func sendErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// RegisterHandler registra un manejador para una ruta específica
func (s *Server) RegisterHandler(path string, handler HttpHandler) {
	http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		var body []byte
		var err error

		if r.ContentLength > 0 && r.Method != http.MethodGet && r.Method != http.MethodHead {
			contentType := r.Header.Get("Content-Type")
			if !strings.HasPrefix(contentType, "application/json") {
				sendErrorResponse(w, http.StatusUnsupportedMediaType,
					"Content-Type must be application/json")
				return
			}

			body, err = io.ReadAll(r.Body)
			if err != nil {
				sendErrorResponse(w, http.StatusBadRequest,
					"Error reading request body")
				return
			}
			defer r.Body.Close()

			if !json.Valid(body) {
				sendErrorResponse(w, http.StatusBadRequest,
					"Invalid JSON format")
				return
			}
		}

		authHeader := r.Header.Get("Authorization")
		username, password, bearerToken := "", "", ""

		if authHeader != "" {
			if u, p, ok := parseBasicAuth(authHeader); ok {
				username, password = u, p
			} else if token, ok := parseBearerToken(authHeader); ok {
				bearerToken = token
			}
		}

		req := &HttpRequest{
			Method:      r.Method,
			Path:        r.URL.Path,
			Body:        string(body),
			ClientIP:    getClientIP(r),
			Headers:     getHeadersString(r),
			Username:    username,
			Password:    password,
			BearerToken: bearerToken,
		}

		response := handler(req)

		if response == nil {
			sendErrorResponse(w, http.StatusInternalServerError,
				"Handler returned nil response")
			return
		}

		w.WriteHeader(response.StatusCode)
		if response.Body != "" {
			w.Write([]byte(response.Body))
		}
	})
}

func CreateResponse(statusCode int, body string) *HttpResponse {
    // Si no se proporcionan parámetros (valores cero)
    if statusCode == 0 && body == "" {
        return &HttpResponse{
            StatusCode: 200,  // Valor por defecto
            Body:       "",   // Cuerpo vacío
        }
    }
    
    return &HttpResponse{
        StatusCode: statusCode,
        Body:       body,
    }
}

// IP List Management
func (s *Server) AddToWhitelist(ip string) bool {
	if net.ParseIP(ip) == nil {
		return false
	}

	s.ipListManager.mu.Lock()
	defer s.ipListManager.mu.Unlock()

	s.ipListManager.whitelist[ip] = true
	delete(s.ipListManager.blacklist, ip)
	return true
}

func (s *Server) RemoveFromWhitelist(ip string) {
	s.ipListManager.mu.Lock()
	defer s.ipListManager.mu.Unlock()
	delete(s.ipListManager.whitelist, ip)
}

func (s *Server) AddToBlacklist(ip string) bool {
	if net.ParseIP(ip) == nil {
		return false
	}

	s.ipListManager.mu.Lock()
	defer s.ipListManager.mu.Unlock()

	s.ipListManager.blacklist[ip] = true
	delete(s.ipListManager.whitelist, ip)
	return true
}

func (s *Server) RemoveFromBlacklist(ip string) {
	s.ipListManager.mu.Lock()
	defer s.ipListManager.mu.Unlock()
	delete(s.ipListManager.blacklist, ip)
}

func (s *Server) IsWhitelisted(ip string) bool {
	s.ipListManager.mu.RLock()
	defer s.ipListManager.mu.RUnlock()
	_, exists := s.ipListManager.whitelist[ip]
	return exists
}

func (s *Server) IsBlacklisted(ip string) bool {
	s.ipListManager.mu.RLock()
	defer s.ipListManager.mu.RUnlock()
	_, exists := s.ipListManager.blacklist[ip]
	return exists
}

func (s *Server) LoadWhitelist(ips []string) {
	s.ipListManager.mu.Lock()
	defer s.ipListManager.mu.Unlock()

	s.ipListManager.whitelist = make(map[string]bool)
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if net.ParseIP(ip) != nil {
			s.ipListManager.whitelist[ip] = true
		}
	}
}

func (s *Server) LoadBlacklist(ips []string) {
	s.ipListManager.mu.Lock()
	defer s.ipListManager.mu.Unlock()

	s.ipListManager.blacklist = make(map[string]bool)
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if net.ParseIP(ip) != nil {
			s.ipListManager.blacklist[ip] = true
		}
	}
}

// Token Management
func (s *Server) SetTokenSecretKey(key string) {
	s.tokenManager.mu.Lock()
	defer s.tokenManager.mu.Unlock()
	s.tokenManager.secretKey = key
}

func (s *Server) SetDefaultTokenExpiry(seconds int) {
	s.tokenManager.mu.Lock()
	defer s.tokenManager.mu.Unlock()
	s.tokenManager.tokenExpiry = time.Duration(seconds) * time.Second
}

func (s *Server) GenerateToken() string {
	s.tokenManager.mu.Lock()
	defer s.tokenManager.mu.Unlock()

	token := fmt.Sprintf("%x-%x-%x",
		time.Now().UnixNano(),
		rand.Int63(),
		rand.Int63())

	expiration := time.Now().Add(s.tokenManager.tokenExpiry)
	s.tokenManager.tokens[token] = expiration

	return token
}

func (s *Server) ValidateToken(token string) int {
	s.tokenManager.mu.RLock()
	defer s.tokenManager.mu.RUnlock()

	expiration, exists := s.tokenManager.tokens[token]
	if !exists {
		return 0 // Token no existe
	}

	if time.Now().After(expiration) {
		return -1 // Token expirado
	}

	if time.Until(expiration) <= time.Millisecond {
		return 0 // Considerar como expirado si está muy cerca
	}

	return 1 // Token válido
}

func (s *Server) InvalidateToken(token string) {
	s.tokenManager.mu.Lock()
	defer s.tokenManager.mu.Unlock()
	delete(s.tokenManager.tokens, token)
}

func (s *Server) GetTokenExpiration(token string) time.Time {
	s.tokenManager.mu.RLock()
	defer s.tokenManager.mu.RUnlock()
	return s.tokenManager.tokens[token]
}

func (s *Server) SetTokenExpiration(token string, expiration time.Time) bool {
	s.tokenManager.mu.Lock()
	defer s.tokenManager.mu.Unlock()

	if _, exists := s.tokenManager.tokens[token]; exists {
		s.tokenManager.tokens[token] = expiration
		return true
	}

	return false
}

func (s *Server) CleanExpiredTokens() int {
	s.tokenManager.mu.Lock()
	defer s.tokenManager.mu.Unlock()

	count := 0
	now := time.Now()

	for token, expiration := range s.tokenManager.tokens {
		if now.After(expiration) {
			delete(s.tokenManager.tokens, token)
			count++
		}
	}

	return count
}

func (s *Server) GetTokenRemainingTime(token string) float64 {
	s.tokenManager.mu.RLock()
	defer s.tokenManager.mu.RUnlock()

	if expiration, exists := s.tokenManager.tokens[token]; exists {
		return time.Until(expiration).Seconds()
	}

	return -1.0
}

// Middleware para verificación de IP
func (s *Server) ipFilterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)

		s.ipListManager.mu.RLock()
		defer s.ipListManager.mu.RUnlock()

		if _, blacklisted := s.ipListManager.blacklist[clientIP]; blacklisted {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if len(s.ipListManager.whitelist) > 0 {
			if _, whitelisted := s.ipListManager.whitelist[clientIP]; !whitelisted {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// Start inicia el servidor HTTP
func (s *Server) Start(port string, enableFilter bool, certFile, keyFile string) error {
	var handler http.Handler = http.DefaultServeMux
	if enableFilter {
		handler = s.ipFilterMiddleware(handler)
	}

	server := &http.Server{
		Addr:    ":" + port,
		Handler: handler,
	}

	if certFile != "" && keyFile != "" {
		return server.ListenAndServeTLS(certFile, keyFile)
	}
	return server.ListenAndServe()
}