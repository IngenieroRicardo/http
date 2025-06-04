package main


/*
#include <stdlib.h>
#include <string.h>

typedef struct {
    char* method;
    char* url;
    char* body;
    size_t body_len;
    char* remote_addr;
    char* headers;
} HttpRequest;

typedef struct {
    char* data;
    size_t len;
    int status_code;
    char* content_type;
} HttpResponse;

typedef void (*HttpHandler)(HttpRequest* req, HttpResponse* resp);

static inline void callCHandler(HttpHandler handler, HttpRequest* req, HttpResponse* resp) {
    if (handler) handler(req, resp);
}

// Estructura para tokens
typedef struct {
    char* token;
    time_t expiration;
} TokenInfo;

*/
import "C"
import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"unsafe"
	"time"
	"sync"
	"math/rand"
	"fmt"
	"encoding/base64"
	"net"
)

func decodeBase64(input *C.char, output **C.char) C.size_t {
	encoded := C.GoString(input)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return 0
	}
	
	*output = (*C.char)(C.malloc(C.size_t(len(decoded))))
	if *output == nil {
		return 0
	}
	
	C.memcpy(unsafe.Pointer(*output), unsafe.Pointer(&decoded[0]), C.size_t(len(decoded)))
	return C.size_t(len(decoded))
}
func extractIP(remoteAddr string) string {
    // Eliminar el puerto
    ip := remoteAddr
    if strings.LastIndex(ip, ":") > strings.LastIndex(ip, "]") {
        ip = ip[:strings.LastIndex(ip, ":")]
    }
    
    // Eliminar corchetes de IPv6
    if strings.HasPrefix(ip, "[") && strings.HasSuffix(ip, "]") {
        ip = ip[1:len(ip)-1]
    }
    
    return ip
}

func getClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}
















//export SetResponseStatusCode
func SetResponseStatusCode(resp *C.HttpResponse, code C.int) {
	if resp != nil {
		resp.status_code = code
	}
}

//export SetResponseContentType
func SetResponseContentType(resp *C.HttpResponse, contentType *C.char) {
	if resp == nil || contentType == nil {
		return
	}

	// Liberar el content_type anterior si existe
	if resp.content_type != nil {
		C.free(unsafe.Pointer(resp.content_type))
	}

	resp.content_type = C.CString(C.GoString(contentType))
}

//export SetResponseText
func SetResponseText(resp *C.HttpResponse, text *C.char) {
    if resp == nil || text == nil {
        return
    }

    // Liberar datos anteriores si existen
    if resp.data != nil {
        C.free(unsafe.Pointer(resp.data))
    }

    str := C.GoString(text)
    resp.data = C.CString(str)
    resp.len = C.size_t(len(str))
}

//export SetResponseBinary
func SetResponseBinary(resp *C.HttpResponse, base64Data *C.char) {
    if resp == nil || base64Data == nil {
		return
	}

	// Liberar datos anteriores si existen
	if resp.data != nil {
		C.free(unsafe.Pointer(resp.data))
		resp.data = nil
		resp.len = 0
	}

	var decodedData *C.char
	decodedLen := decodeBase64(base64Data, &decodedData)
	
	if decodedLen > 0 && decodedData != nil {
		resp.data = decodedData
		resp.len = decodedLen
	}
}

//export RegisterHandler
func RegisterHandler(path *C.char, handler C.HttpHandler) {
	pathStr := C.GoString(path)
	
	http.HandleFunc(pathStr, func(w http.ResponseWriter, r *http.Request) {
		// Leer cuerpo del request
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading body", http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		// Convertir headers a JSON
		headersJson, err := json.Marshal(r.Header)
		if err != nil {
			http.Error(w, "Error marshaling headers", http.StatusInternalServerError)
			return
		}

		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "Error contentType headers", http.StatusInternalServerError)
			return
		}


		// Crear request - SIN defer para los campos internos
        creq := (*C.HttpRequest)(C.calloc(1, C.sizeof_HttpRequest))
        creq.method = C.CString(r.Method)
        creq.url = C.CString(r.URL.String())
        creq.body = (*C.char)(C.CBytes(body))
        creq.body_len = C.size_t(len(body))
        ip := extractIP(r.RemoteAddr)
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		    ip = strings.TrimSpace(strings.Split(forwarded, ",")[0])
		}
		creq.remote_addr = C.CString(ip)
        creq.headers = C.CString(string(headersJson))

        // Crear response - SIN defer para data
        cresp := (*C.HttpResponse)(C.calloc(1, C.sizeof_HttpResponse))
        cresp.status_code = 200
        cresp.content_type = C.CString("text/plain; charset=utf-8")

        // Llamar al handler
        C.callCHandler(handler, creq, cresp)


		// Escribir respuesta
        if cresp.content_type != nil {
            w.Header().Set("Content-Type", C.GoString(cresp.content_type))
        }
        w.WriteHeader(int(cresp.status_code))
        if cresp.data != nil {
            w.Write([]byte(C.GoStringN(cresp.data, C.int(cresp.len))))
        }

        // Liberación ÚNICA y ORDENADA
        C.free(unsafe.Pointer(creq.method))
        C.free(unsafe.Pointer(creq.url))
        C.free(unsafe.Pointer(creq.body))
        C.free(unsafe.Pointer(creq.remote_addr))
        C.free(unsafe.Pointer(creq.headers))
        C.free(unsafe.Pointer(creq))
        
        C.free(unsafe.Pointer(cresp.content_type))
        if cresp.data != nil {
            C.free(unsafe.Pointer(cresp.data))
        }
        C.free(unsafe.Pointer(cresp))
	})
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

// ---------- Funciones de gestión de listas ----------

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

//export StartServerWithIPFilter
func StartServerWithIPFilter(port *C.char, enableFilter C.int) {
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
		
		if err := server.ListenAndServe(); err != nil {
			panic(err)
		}
	}()
}

// Función auxiliar para cargar listas desde strings separados por comas
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














// ---------------------------------------------------------------------------------------




//export GetRequestMethod
func GetRequestMethod(req *C.HttpRequest) *C.char {
    if req == nil {
        return nil
    }
    return req.method
}

//export GetRequestURL
func GetRequestURL(req *C.HttpRequest) *C.char {
    if req == nil {
        return nil
    }
    return req.url
}

//export GetRequestBody
func GetRequestBody(req *C.HttpRequest, length *C.size_t) *C.char {
    if req == nil || length == nil {
        return nil
    }
    *length = req.body_len
    return req.body
}

//export GetRequestRemoteAddr
func GetRequestRemoteAddr(req *C.HttpRequest) *C.char {
    if req == nil {
        return nil
    }
    return req.remote_addr
}

//export GetRequestHeader
func GetRequestHeader(req *C.HttpRequest, key *C.char) *C.char {
    if req == nil || key == nil || req.headers == nil {
        return nil
    }
    headersJson := C.GoString(req.headers)
    var headers map[string][]string
    if err := json.Unmarshal([]byte(headersJson), &headers); err != nil {
        return nil
    }

    goKey := C.GoString(key)
    if values, exists := headers[goKey]; exists && len(values) > 0 {
        // IMPORTANTE: El caller debe liberar este string
        return C.CString(values[0])
    }
    return nil
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

// ---------- Funciones de gestión de tokens ----------

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