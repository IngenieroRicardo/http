package main

/*
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Estructura para tokens
typedef struct {
    char* token;
    time_t expiration;
} TokenInfo;

typedef struct {
    const char* method;
    const char* path;
    const char* body;
    const char* client_ip;
    const char* headers;
    const char* username;
    const char* password;
    const char* bearer_token;
} HttpRequest;

typedef struct {
    int status_code;
    const char* body;
} HttpResponse;

typedef HttpRequest* Request;
typedef HttpResponse* Response;

typedef Response (*HttpHandler)(Request req);

// Nueva función para liberar respuestas
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
	"io"
	"net/http"
	"strings"
	"unsafe"
	"net"
	"encoding/base64"
	"encoding/json"
	"sync"
	"time"
	"math/rand"
	"fmt"
)

// Función para extraer username y password del header Authorization
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

// Función para extraer token Bearer del header Authorization
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

// Implementar un pool de memoria para requests
var requestPool = sync.Pool{
    New: func() interface{} {
        return &C.HttpRequest{}
    },
}





//export RegisterHandler
func RegisterHandler(path *C.char, handler C.HttpHandler) {
    goPath := C.GoString(path)
    http.HandleFunc(goPath, func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")

        // Obtener request del pool
        req := requestPool.Get().(*C.HttpRequest)
        defer requestPool.Put(req)

        // Resetear los campos del request
        *req = C.HttpRequest{} // Limpiar la estructura

        // Configurar campos del request
        req.method = C.CString(r.Method)
        req.path = C.CString(r.URL.Path)
        req.client_ip = C.CString(getClientIP(r))
        req.headers = C.CString(getHeadersString(r))

        // Manejo del body con tamaño máximo
        if r.ContentLength > 0 && r.ContentLength < 10*1024*1024 { // 10MB máximo
            body, _ := io.ReadAll(r.Body)
            r.Body.Close()
            req.body = C.CString(string(body))
        }

        // Procesar autenticación
        if authHeader := r.Header.Get("Authorization"); authHeader != "" {
            if u, p, ok := parseBasicAuth(authHeader); ok {
                req.username = C.CString(u)
                req.password = C.CString(p)
            } else if token, ok := parseBearerToken(authHeader); ok {
                req.bearer_token = C.CString(token)
            }
        }

        // Llamar al handler C
        cResponse := C.call_handler(handler, req)
        defer C.FreeResponse(cResponse) // Usar nueva función de liberación

        // Manejar respuesta
        if cResponse != nil {
            w.WriteHeader(int(cResponse.status_code))
            if cResponse.body != nil {
                w.Write([]byte(C.GoString(cResponse.body)))
            }
        } else {
            sendErrorResponse(w, http.StatusInternalServerError, "Handler returned nil response")
        }

        // Liberar strings C (optimizado)
        freeRequestStrings(req)
    })
}

// Función optimizada para liberar strings
func freeRequestStrings(req *C.HttpRequest) {
    if req.method != nil { C.free(unsafe.Pointer(req.method)) }
    if req.path != nil { C.free(unsafe.Pointer(req.path)) }
    if req.body != nil { C.free(unsafe.Pointer(req.body)) }
    if req.client_ip != nil { C.free(unsafe.Pointer(req.client_ip)) }
    if req.headers != nil { C.free(unsafe.Pointer(req.headers)) }
    if req.username != nil { C.free(unsafe.Pointer(req.username)) }
    if req.password != nil { C.free(unsafe.Pointer(req.password)) }
    if req.bearer_token != nil { C.free(unsafe.Pointer(req.bearer_token)) }
}







// Función helper para enviar respuestas de error
func sendErrorResponse(w http.ResponseWriter, statusCode int, message string) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(statusCode)
    json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// Modificar freeRequest para liberar el nuevo campo
func freeRequest(req *C.HttpRequest) {
	C.free(unsafe.Pointer(req.method))
	C.free(unsafe.Pointer(req.path))
	C.free(unsafe.Pointer(req.body))
	C.free(unsafe.Pointer(req.client_ip))
	C.free(unsafe.Pointer(req.headers))
	C.free(unsafe.Pointer(req.username))
	C.free(unsafe.Pointer(req.password))
	C.free(unsafe.Pointer(req.bearer_token))
}

//export GetMethod
func GetMethod(req *C.HttpRequest) *C.char {
    if req == nil || req.method == nil {
        return nil
    }
    return C.strdup(req.method)
}

//export GetPath
func GetPath(req *C.HttpRequest) *C.char {
    if req == nil || req.path == nil {
        return nil
    }
    return C.strdup(req.path)
}

//export GetBody
func GetBody(req *C.HttpRequest) *C.char {
    if req == nil || req.path == nil {
        return nil
    }
    return C.strdup(req.body)
}

//export GetClientIP
func GetClientIP(req *C.HttpRequest) *C.char {
    if req == nil || req.path == nil {
        return nil
    }
    return C.strdup(req.client_ip)
}

//export GetHeaders
func GetHeaders(req *C.HttpRequest) *C.char {
    if req == nil || req.path == nil {
        return nil
    }
    return C.strdup(req.headers)
}

//export GetHeaderValue
func GetHeaderValue(req *C.HttpRequest, key *C.char) *C.char {
    if req == nil || key == nil || req.headers == nil {
        return nil
    }

    keyStr := C.GoString(key)
    headersStr := C.GoString(req.headers)
    headers := strings.Split(headersStr, "\n")

    for _, header := range headers {
        parts := strings.SplitN(header, ": ", 2)
        if len(parts) == 2 && strings.EqualFold(parts[0], keyStr) {
            return C.strdup(C.CString(parts[1]))
        }
    }
    return nil
}

//export GetUsername
func GetUsername(req *C.HttpRequest) *C.char {
    if req == nil {
        return nil
    }
    return req.username
}

//export GetPassword
func GetPassword(req *C.HttpRequest) *C.char {
    if req == nil {
        return nil
    }
    return req.password
}

//export GetBearerToken
func GetBearerToken(req *C.HttpRequest) *C.char {
    if req == nil {
        return nil
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
        res.body = C.strdup(body) // Copia que debe ser liberada
    }
    
    return res
}

// ListManager gestiona las listas de IPs
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
		return 0 // IP inválida
	}

	ipListManager.mu.Lock()
	defer ipListManager.mu.Unlock()
	
	ipListManager.whitelist[ipStr] = true
	// Si está en blacklist, la quitamos
	delete(ipListManager.blacklist, ipStr)
	
	return 1 // Éxito
}

//export RemoveFromWhitelist
func RemoveFromWhitelist(ip *C.char) C.int {
	ipStr := C.GoString(ip)
	
	ipListManager.mu.Lock()
	defer ipListManager.mu.Unlock()
	
	delete(ipListManager.whitelist, ipStr)
	return 1
}

//export AddToBlacklist
func AddToBlacklist(ip *C.char) C.int {
	ipStr := C.GoString(ip)
	if net.ParseIP(ipStr) == nil {
		return 0 // IP inválida
	}

	ipListManager.mu.Lock()
	defer ipListManager.mu.Unlock()
	
	ipListManager.blacklist[ipStr] = true
	// Si está en whitelist, la quitamos
	delete(ipListManager.whitelist, ipStr)
	
	return 1 // Éxito
}

//export RemoveFromBlacklist
func RemoveFromBlacklist(ip *C.char) C.int {
	ipStr := C.GoString(ip)
	
	ipListManager.mu.Lock()
	defer ipListManager.mu.Unlock()
	
	delete(ipListManager.blacklist, ipStr)
	return 1
}

//export IsWhitelisted
func IsWhitelisted(ip *C.char) C.int {
	ipStr := C.GoString(ip)
	
	ipListManager.mu.RLock()
	defer ipListManager.mu.RUnlock()
	
	if _, exists := ipListManager.whitelist[ipStr]; exists {
		return 1
	}
	return 0
}

//export IsBlacklisted
func IsBlacklisted(ip *C.char) C.int {
	ipStr := C.GoString(ip)
	
	ipListManager.mu.RLock()
	defer ipListManager.mu.RUnlock()
	
	if _, exists := ipListManager.blacklist[ipStr]; exists {
		return 1
	}
	return 0
}

// Middleware para verificación de IP
func ipFilterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		
		ipListManager.mu.RLock()
		defer ipListManager.mu.RUnlock()
		
		// Primero verificar blacklist
		if _, blacklisted := ipListManager.blacklist[clientIP]; blacklisted {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		
		// Si hay whitelist, verificar
		if len(ipListManager.whitelist) > 0 {
			if _, whitelisted := ipListManager.whitelist[clientIP]; !whitelisted {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		
		next.ServeHTTP(w, r)
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
        
        // Si se proporcionan certificados, usar HTTPS
        if certFile != nil && keyFile != nil {
            cert := C.GoString(certFile)
            key := C.GoString(keyFile)
            
            if err := server.ListenAndServeTLS(cert, key); err != nil {
                panic("Error al iniciar servidor HTTPS: " + err.Error())
            }
        } else {
            // Sin certificados, usar HTTP
            if err := server.ListenAndServe(); err != nil {
                panic("Error al iniciar servidor HTTP: " + err.Error())
            }
        }
    }()
}

//export LoadWhitelist
func LoadWhitelist(ips *C.char) {
	ipStr := C.GoString(ips)
	ipList := strings.Split(ipStr, ",")
	
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
	ipStr := C.GoString(ips)
	ipList := strings.Split(ipStr, ",")
	
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

// TokenManager gestiona tokens de autenticación
type TokenManager struct {
	tokens      map[string]time.Time // token -> expiration time
	secretKey   string               // clave secreta para validación (opcional)
	mu          sync.RWMutex
	tokenExpiry time.Duration       // duración por defecto de los tokens
}

var tokenManager = &TokenManager{
	tokens:    make(map[string]time.Time),
	secretKey: "default-secret-key", // Cambiar en producción
	tokenExpiry: 24 * time.Hour,    // 24 horas por defecto
}

//export SetTokenSecretKey
func SetTokenSecretKey(key *C.char) {
	tokenManager.mu.Lock()
	defer tokenManager.mu.Unlock()
	tokenManager.secretKey = C.GoString(key)
}

//export SetDefaultTokenExpiry
func SetDefaultTokenExpiry(seconds C.int) {
	tokenManager.mu.Lock()
	defer tokenManager.mu.Unlock()
	tokenManager.tokenExpiry = time.Duration(seconds) * time.Second
}

//export GenerateToken
func GenerateToken() *C.char {
	tokenManager.mu.Lock()
	defer tokenManager.mu.Unlock()
	// Generar un token único (en producción usar un método más seguro)
	token := fmt.Sprintf("%x-%x-%x", 
		time.Now().UnixNano(), 
		rand.Int63(), 
		rand.Int63())
	
	expiration := time.Now().Add(tokenManager.tokenExpiry)
	tokenManager.tokens[token] = expiration
	
	return C.CString(token)
}

//export ValidateToken
func ValidateToken(token *C.char) C.int {
    tokenStr := C.GoString(token)
    
    tokenManager.mu.RLock()
    defer tokenManager.mu.RUnlock()
    
    expiration, exists := tokenManager.tokens[tokenStr]
    if !exists {
        return 0 // Token no existe
    }
    
    if time.Now().After(expiration) {
        return -1 // Token expirado
    }
    
    // Token válido, calcular margen adicional (1ms) para evitar falsos positivos
    if time.Until(expiration) <= time.Millisecond {
        return 0 // Considerar como expirado si está muy cerca
    }
    
    return 1 // Token válido
}

//export InvalidateToken
func InvalidateToken(token *C.char) {
	tokenStr := C.GoString(token)
	
	tokenManager.mu.Lock()
	defer tokenManager.mu.Unlock()
	
	delete(tokenManager.tokens, tokenStr)
}

//export GetTokenExpiration
func GetTokenExpiration(token *C.char) C.time_t {
	tokenStr := C.GoString(token)
	
	tokenManager.mu.RLock()
	defer tokenManager.mu.RUnlock()
	
	if expiration, exists := tokenManager.tokens[tokenStr]; exists {
		return C.time_t(expiration.Unix())
	}
	
	return 0
}

//export SetTokenExpiration
func SetTokenExpiration(token *C.char, expiration C.time_t) C.int {
	tokenStr := C.GoString(token)
	expTime := time.Unix(int64(expiration), 0)
	
	tokenManager.mu.Lock()
	defer tokenManager.mu.Unlock()
	
	if _, exists := tokenManager.tokens[tokenStr]; exists {
		tokenManager.tokens[tokenStr] = expTime
		return 1
	}
	
	return 0
}

//export CleanExpiredTokens
func CleanExpiredTokens() C.int {
	tokenManager.mu.Lock()
	defer tokenManager.mu.Unlock()
	
	count := 0
	now := time.Now()
	
	for token, expiration := range tokenManager.tokens {
		if now.After(expiration) {
			delete(tokenManager.tokens, token)
			count++
		}
	}
	
	return C.int(count)
}

//export GetTokenInfo
func GetTokenInfo(token *C.char) *C.TokenInfo {
	tokenStr := C.GoString(token)
	
	tokenManager.mu.RLock()
	defer tokenManager.mu.RUnlock()
	
	if expiration, exists := tokenManager.tokens[tokenStr]; exists {
		cToken := C.CString(tokenStr)
		cInfo := &C.TokenInfo{
			token:      cToken,
			expiration: C.time_t(expiration.Unix()),
		}
		// Nota: La memoria de cToken debe ser liberada por el llamador
		return cInfo
	}
	
	return nil
}

//export FreeTokenInfo
func FreeTokenInfo(info *C.TokenInfo) {
	if info == nil {
		return
	}
	
	C.free(unsafe.Pointer(info.token))
	C.free(unsafe.Pointer(info))
}

//export IsTokenValid
func IsTokenValid(token *C.char) C.int {
    return ValidateToken(token)
}

//export GetTokenRemainingTime
func GetTokenRemainingTime(token *C.char) C.double {
    tokenStr := C.GoString(token)
    
    tokenManager.mu.RLock()
    defer tokenManager.mu.RUnlock()
    
    if expiration, exists := tokenManager.tokens[tokenStr]; exists {
        remaining := time.Until(expiration).Seconds()
        return C.double(remaining)
    }
    
    return -1.0 // Token no encontrado
}


func main() {}
