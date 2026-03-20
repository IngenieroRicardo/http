// file http.go

// +build !js

package main

/*
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    const char* method;
    const char* path;
    const char* body;
    const char* client_ip;
    const char* headers;
    const char* username;
    const char* password;
    const char* bearer_token;
    const char* host;
} HttpRequest;

typedef struct {
    int status_code;
    const char* body;
} HttpResponse;

typedef HttpRequest* Request;
typedef HttpResponse* Response;

typedef Response (*HttpHandler)(Request req);

static inline void FreeResponse(Response res) {
    if (res == NULL) return;
    if (res->body != NULL) {
        free((void*)res->body);
    }
    free(res);
}

static inline Response call_handler(HttpHandler handler, Request req) {
    return handler(req);
}

static inline Response create_response_with_params(int status_code, const char* body) {
    Response res = (Response)malloc(sizeof(HttpResponse));
    if (res) {
        res->status_code = status_code;
        res->body = body ? strdup(body) : NULL;
    }
    return res;
}

static inline Response create_response() {
    return create_response_with_params(0, NULL);
}
*/
import "C"
import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/golang-jwt/jwt/v5"
)

var secretKey = []byte("https://github.com/IngenieroRicardo/http")

var credentials = make(map[string]string)

// --- JWT y credenciales ---

//export GenerateToken
func GenerateToken(userid C.int, expiration C.longlong) *C.char {
	claims := jwt.MapClaims{
		"user_id": int(userid),
		"exp":     time.Now().Add(time.Second * time.Duration(expiration)).Unix(),
		"iat":     time.Now().Unix(),
		"iss":     "http-api",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return C.CString(`{"error":"No se pudo generar el token"}`)
	}
	response := map[string]interface{}{
		"access_token": tokenString,
		"token_type":   "Bearer",
		"expires_in":   int64(expiration),
	}
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		return C.CString(`{"error":"No se pudo generar el JSON"}`)
	}
	return C.CString(string(jsonResponse))
}

//export ValidateToken
func ValidateToken(tokenString *C.char) C.int {
	goToken := C.GoString(tokenString)
	token, err := jwt.Parse(goToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("método de firma inválido: %v", token.Header["alg"])
		}
		return secretKey, nil
	})
	if err != nil || !token.Valid {
		return 0
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if exp, ok := claims["exp"].(float64); ok {
			if int64(exp) > time.Now().Unix() {
				return 1
			}
			return 0
		}
	}
	return 0
}

//export LoadCredentials
func LoadCredentials(credenciales *C.char) C.int {
	goStr := C.GoString(credenciales)
	newCreds := make(map[string]string)
	pairs := strings.Split(goStr, ",")
	for _, pair := range pairs {
		partes := strings.SplitN(pair, ":", 2)
		if len(partes) != 2 {
			return 0
		}
		user := strings.TrimSpace(partes[0])
		pass := strings.TrimSpace(partes[1])
		if user == "" || pass == "" {
			return 0
		}
		newCreds[user] = pass
	}
	credentials = newCreds
	return 1
}

//export ValidateCredential
func ValidateCredential(usuario *C.char, contrasena *C.char) C.int {
	if storedPass, ok := credentials[C.GoString(usuario)]; ok && storedPass == C.GoString(contrasena) {
		return 1
	}
	return 0
}

// --- Helpers internos ---

func parseBasicAuth(authHeader string) (string, string, bool) {
	if !strings.HasPrefix(authHeader, "Basic ") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(authHeader[6:])
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func parseBearerToken(authHeader string) (string, bool) {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", false
	}
	return authHeader[7:], true
}

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

func getHeadersJSON(r *http.Request) string {
	headers, _ := json.Marshal(r.Header)
	return string(headers)
}

func sendErrorResponse(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func freeRequest(req *C.HttpRequest) {
	C.free(unsafe.Pointer(req.method))
	C.free(unsafe.Pointer(req.path))
	C.free(unsafe.Pointer(req.body))
	C.free(unsafe.Pointer(req.client_ip))
	C.free(unsafe.Pointer(req.headers))
	C.free(unsafe.Pointer(req.username))
	C.free(unsafe.Pointer(req.password))
	C.free(unsafe.Pointer(req.bearer_token))
	C.free(unsafe.Pointer(req.host))
}

// --- RegisterHandler y StartServer ---

//export RegisterHandler
func RegisterHandler(path *C.char, handler C.HttpHandler) {
	goPath := C.GoString(path)
	http.HandleFunc(goPath, func(w http.ResponseWriter, r *http.Request) {
		// Cabeceras de seguridad
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data: https:; "+
				"font-src 'self'; "+
				"connect-src 'self'; "+
				"object-src 'none'; "+
				"frame-ancestors 'none';")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		if r.TLS != nil || strings.ToLower(r.Header.Get("X-Forwarded-Proto")) == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		w.Header().Set("Content-Type", "application/json")

		// Leer body con las mismas validaciones que la versión Go
		var bodyStr string
		if r.ContentLength > 0 {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				contentType := r.Header.Get("Content-Type")
				if !strings.HasPrefix(contentType, "application/json") {
					sendErrorResponse(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
					return
				}
			}
			body, err := io.ReadAll(r.Body)
			r.Body.Close()
			if err != nil {
				sendErrorResponse(w, http.StatusBadRequest, "Error reading request body")
				return
			}
			if len(body) > 0 && r.Method != http.MethodGet && r.Method != http.MethodHead {
				if !json.Valid(body) {
					sendErrorResponse(w, http.StatusBadRequest, "Invalid JSON format")
					return
				}
			}
			bodyStr = string(body)
		}

		// Autenticación: siempre inicializar a ""
		username, password, bearerToken := "", "", ""
		if authHeader := r.Header.Get("Authorization"); authHeader != "" {
			if u, p, ok := parseBasicAuth(authHeader); ok {
				username, password = u, p
			} else if token, ok := parseBearerToken(authHeader); ok {
				bearerToken = token
			}
		}

		// Construir el request C
		req := &C.HttpRequest{
			method:       C.CString(r.Method),
			path:         C.CString(r.URL.Path),
			body:         C.CString(bodyStr),
			client_ip:    C.CString(getClientIP(r)),
			headers:      C.CString(getHeadersJSON(r)),
			username:     C.CString(username),
			password:     C.CString(password),
			bearer_token: C.CString(bearerToken),
			host:         C.CString(r.Host),
		}
		defer freeRequest(req)

		cResponse := C.call_handler(handler, req)
		defer C.FreeResponse(cResponse)

		if cResponse != nil {
			w.WriteHeader(int(cResponse.status_code))
			if cResponse.body != nil {
				w.Write([]byte(C.GoString(cResponse.body)))
			}
		} else {
			sendErrorResponse(w, http.StatusInternalServerError, "Handler returned nil response")
		}
	})
}

//export StartServer
func StartServer(port *C.char, enableFilter C.int, certFile *C.char, keyFile *C.char) {
	portStr := C.GoString(port)

	var handler http.Handler = http.DefaultServeMux
	if enableFilter == 1 {
		handler = ipFilterMiddleware(handler)
	}

	go func() {
		server := &http.Server{
			Addr:    ":" + portStr,
			Handler: handler,
		}
		var err error
		if certFile != nil && keyFile != nil {
			cert := C.GoString(certFile)
			key := C.GoString(keyFile)
			if cert != "" && key != "" {
				err = server.ListenAndServeTLS(cert, key)
			} else {
				err = server.ListenAndServe()
			}
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			panic("Error al iniciar servidor: " + err.Error())
		}
	}()
}

// --- Getters exportados ---

//export GetHost
func GetHost(req *C.HttpRequest) *C.char {
	if req == nil || req.host == nil {
		return C.CString("")
	}
	return req.host
}

//export GetMethod
func GetMethod(req *C.HttpRequest) *C.char {
	if req == nil || req.method == nil {
		return C.CString("")
	}
	return req.method
}

//export GetPath
func GetPath(req *C.HttpRequest) *C.char {
	if req == nil || req.path == nil {
		return C.CString("")
	}
	return req.path
}

//export GetBody
func GetBody(req *C.HttpRequest) *C.char {
	if req == nil || req.body == nil {
		return C.CString("")
	}
	return req.body
}

//export GetClientIP
func GetClientIP(req *C.HttpRequest) *C.char {
	if req == nil || req.client_ip == nil {
		return C.CString("")
	}
	return req.client_ip
}

//export GetHeaders
func GetHeaders(req *C.HttpRequest) *C.char {
	if req == nil || req.headers == nil {
		return C.CString("")
	}
	return req.headers
}

//export GetHeaderValue
func GetHeaderValue(req *C.HttpRequest, key *C.char) *C.char {
	if req == nil || key == nil || req.headers == nil {
		return C.CString("")
	}
	var headers map[string][]string
	if err := json.Unmarshal([]byte(C.GoString(req.headers)), &headers); err != nil {
		return C.CString("")
	}
	keyStr := strings.ToLower(C.GoString(key))
	for name, values := range headers {
		if strings.ToLower(name) == keyStr && len(values) > 0 {
			return C.CString(values[0])
		}
	}
	return C.CString("")
}

//export GetUsername
func GetUsername(req *C.HttpRequest) *C.char {
	if req == nil || req.username == nil {
		return C.CString("")
	}
	return req.username
}

//export GetPassword
func GetPassword(req *C.HttpRequest) *C.char {
	if req == nil || req.password == nil {
		return C.CString("")
	}
	return req.password
}

//export GetBearerToken
func GetBearerToken(req *C.HttpRequest) *C.char {
	if req == nil || req.bearer_token == nil {
		return C.CString("")
	}
	return req.bearer_token
}

//export CreateResponse
func CreateResponse(statusCode C.int, body *C.char) *C.HttpResponse {
	res := (*C.HttpResponse)(C.malloc(C.sizeof_HttpResponse))
	if res == nil {
		return nil
	}
	res.status_code = statusCode
	res.body = nil
	if body != nil {
		res.body = C.strdup(body)
	}
	return res
}

// --- IP filtering ---

type ListManager struct {
	whitelist map[string]bool
	blacklist map[string]bool
	mu        sync.RWMutex
}

var ipListManager = &ListManager{
	whitelist: make(map[string]bool),
	blacklist: make(map[string]bool),
}

//export AddToWhitelist
func AddToWhitelist(ip *C.char) C.int {
	ipStr := C.GoString(ip)
	if net.ParseIP(ipStr) == nil {
		return 0
	}
	ipListManager.mu.Lock()
	defer ipListManager.mu.Unlock()
	ipListManager.whitelist[ipStr] = true
	delete(ipListManager.blacklist, ipStr)
	return 1
}

//export RemoveFromWhitelist
func RemoveFromWhitelist(ip *C.char) C.int {
	ipListManager.mu.Lock()
	defer ipListManager.mu.Unlock()
	delete(ipListManager.whitelist, C.GoString(ip))
	return 1
}

//export AddToBlacklist
func AddToBlacklist(ip *C.char) C.int {
	ipStr := C.GoString(ip)
	if net.ParseIP(ipStr) == nil {
		return 0
	}
	ipListManager.mu.Lock()
	defer ipListManager.mu.Unlock()
	ipListManager.blacklist[ipStr] = true
	delete(ipListManager.whitelist, ipStr)
	return 1
}

//export RemoveFromBlacklist
func RemoveFromBlacklist(ip *C.char) C.int {
	ipListManager.mu.Lock()
	defer ipListManager.mu.Unlock()
	delete(ipListManager.blacklist, C.GoString(ip))
	return 1
}

//export IsWhitelisted
func IsWhitelisted(ip *C.char) C.int {
	ipListManager.mu.RLock()
	defer ipListManager.mu.RUnlock()
	if ipListManager.whitelist[C.GoString(ip)] {
		return 1
	}
	return 0
}

//export IsBlacklisted
func IsBlacklisted(ip *C.char) C.int {
	ipListManager.mu.RLock()
	defer ipListManager.mu.RUnlock()
	if ipListManager.blacklist[C.GoString(ip)] {
		return 1
	}
	return 0
}

func ipFilterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)

		ipListManager.mu.RLock()
		defer ipListManager.mu.RUnlock()

		if ipListManager.blacklist[clientIP] {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if len(ipListManager.whitelist) > 0 && !ipListManager.whitelist[clientIP] {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

//export LoadWhitelist
func LoadWhitelist(ips *C.char) {
	ipList := strings.Split(C.GoString(ips), ",")
	ipListManager.mu.Lock()
	defer ipListManager.mu.Unlock()
	ipListManager.whitelist = make(map[string]bool)
	for _, ip := range ipList {
		ip = strings.TrimSpace(ip)
		if net.ParseIP(ip) != nil {
			ipListManager.whitelist[ip] = true
		}
	}
}

//export LoadBlacklist
func LoadBlacklist(ips *C.char) {
	ipList := strings.Split(C.GoString(ips), ",")
	ipListManager.mu.Lock()
	defer ipListManager.mu.Unlock()
	ipListManager.blacklist = make(map[string]bool)
	for _, ip := range ipList {
		ip = strings.TrimSpace(ip)
		if net.ParseIP(ip) != nil {
			ipListManager.blacklist[ip] = true
		}
	}
}

func main() {}
