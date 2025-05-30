package main

/*
#include <stdlib.h>
#include <string.h>

typedef struct {
    char* method;
    char* path;
    char* body;
    char* client_ip;
    char* headers;
    char* content_type;
} HttpRequest;

typedef struct {
    char* body;
    char* content_type;
    int status_code;
    char* headers;
} HttpResponse;

static HttpResponse* create_http_response() {
    HttpResponse* res = (HttpResponse*)malloc(sizeof(HttpResponse));
    memset(res, 0, sizeof(HttpResponse));
    return res;
}

static void free_http_response(HttpResponse* res) {
    if (res == NULL) return;
    free(res->body);
    free(res->content_type);
    free(res->headers);
    free(res);
}

typedef HttpResponse* (*HttpHandler)(HttpRequest* req);

static HttpResponse* call_handler(HttpHandler handler, HttpRequest* req) {
    return handler(req);
}
*/
import "C"
import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"unsafe"
)

// FormData representa los datos extraídos de un formulario
type FormData struct {
	Values  map[string][]string      // Campos de texto
	Files   map[string][]*FileHeader // Archivos subidos
}

// FileHeader representa la información de un archivo subido
type FileHeader struct {
	Filename string
	Header   textproto.MIMEHeader
	Content  []byte
}

var (
	requestMap sync.Map // Mapa seguro para concurrencia
)

// Función para obtener la IP del cliente
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

// getHeadersString convierte los headers a un string formateado
func getHeadersString(r *http.Request) string {
	var headers strings.Builder
	for name, values := range r.Header {
		// Normalizar nombres de headers
		name = textproto.CanonicalMIMEHeaderKey(name)
		for _, value := range values {
			headers.WriteString(name)
			headers.WriteString(": ")
			headers.WriteString(value)
			headers.WriteString("\r\n")
		}
	}
	return headers.String()
}

// ParseFormData analiza el cuerpo según Content-Type
func ParseFormData(r *http.Request) (*FormData, error) {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		return nil, fmt.Errorf("missing Content-Type")
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("error parsing Content-Type: %v", err)
	}

	result := &FormData{
		Values: make(map[string][]string),
		Files:  make(map[string][]*FileHeader),
	}

	switch {
	case strings.HasPrefix(mediaType, "multipart/"):
		err = parseMultipartFormData(r, params["boundary"], result)
	case mediaType == "application/x-www-form-urlencoded":
		err = parseURLEncodedFormData(r, result)
	default:
		err = fmt.Errorf("unsupported Content-Type: %s", mediaType)
	}

	return result, err
}

func parseMultipartFormData(r *http.Request, boundary string, result *FormData) error {
	reader := multipart.NewReader(r.Body, boundary)
	
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading multipart section: %v", err)
		}

		content, err := io.ReadAll(part)
		if err != nil {
			return fmt.Errorf("error reading part content: %v", err)
		}

		name := part.FormName()
		if name == "" {
			continue
		}

		if filename := part.FileName(); filename != "" {
			fileHeader := &FileHeader{
				Filename: filename,
				Header:   part.Header,
				Content:  content,
			}
			result.Files[name] = append(result.Files[name], fileHeader)
		} else {
			result.Values[name] = append(result.Values[name], string(content))
		}
	}
	
	return nil
}

func parseURLEncodedFormData(r *http.Request, result *FormData) error {
	if r.Body == nil {
		return fmt.Errorf("missing form body")
	}
	
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("error reading body: %v", err)
	}
	
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return fmt.Errorf("error parsing form data: %v", err)
	}
	
	for k, v := range values {
		result.Values[k] = v
	}
	
	return nil
}

//export GetFormValue
func GetFormValue(req *C.HttpRequest, key *C.char) *C.char {
	keyStr := C.GoString(key)
	
	if data, ok := requestMap.Load(uintptr(unsafe.Pointer(req))); ok {
		formData := data.(*FormData)
		
		if values, ok := formData.Values[keyStr]; ok && len(values) > 0 {
			return C.CString(values[0])
		}
		
		if files, ok := formData.Files[keyStr]; ok && len(files) > 0 {
			file := files[0]
			base64Str := base64.StdEncoding.EncodeToString(file.Content)
			return C.CString(base64Str)
		}
	}
	
	return nil
}

//export GetHeaderValue
func GetHeaderValue(req *C.HttpRequest, headerName *C.char) *C.char {
    goHeaders := C.GoString(req.headers)
    goHeaderName := textproto.CanonicalMIMEHeaderKey(C.GoString(headerName))
    
    // Caso especial para Authorization (algunos clientes pueden usar "authorization" en minúsculas)
    if goHeaderName == "Authorization" {
        goHeaderName = "Authorization"
    }
    
    headerLines := strings.Split(goHeaders, "\r\n")
    
    for _, line := range headerLines {
        if idx := strings.Index(line, ":"); idx > 0 {
            name := strings.TrimSpace(line[:idx])
            if textproto.CanonicalMIMEHeaderKey(name) == goHeaderName {
                value := strings.TrimSpace(line[idx+1:])
                return C.CString(value)
            }
        }
    }
    
    return nil
}

//export RegisterHandler
func RegisterHandler(path *C.char, handler C.HttpHandler) {
	pathStr := C.GoString(path)
	http.HandleFunc(pathStr, func(w http.ResponseWriter, r *http.Request) {
		// Leer y restaurar el body
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusInternalServerError)
			return
		}
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// Parsear el formulario si es necesario
		var formData *FormData
		contentType := r.Header.Get("Content-Type");
		if contentType != "" {
			formData, err = ParseFormData(r)
			if err != nil {
				fmt.Printf("Warning: error parsing form data: %v\n", err)
			}
		}

		// Crear HttpRequest para C
		req := &C.HttpRequest{
			method:       C.CString(r.Method),
			path:         C.CString(r.URL.Path),
			body:         C.CString(string(bodyBytes)),
			client_ip:    C.CString(getClientIP(r)),
			headers:      C.CString(getHeadersString(r)),
			content_type: C.CString(contentType),
		}
		defer func() {
			C.free(unsafe.Pointer(req.method))
			C.free(unsafe.Pointer(req.path))
			C.free(unsafe.Pointer(req.body))
			C.free(unsafe.Pointer(req.client_ip))
			C.free(unsafe.Pointer(req.headers))
			C.free(unsafe.Pointer(req.content_type))
		}()

		// Almacenar formData si existe
		if formData != nil {
			requestMap.Store(uintptr(unsafe.Pointer(req)), formData)
			defer requestMap.Delete(uintptr(unsafe.Pointer(req)))
		}

		// Llamar al handler de C
		cRes := C.call_handler(handler, req)
		if cRes == nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer C.free_http_response(cRes)

		// Configurar headers de respuesta
		if cRes.headers != nil {
			headers := strings.Split(C.GoString(cRes.headers), "\n")
			for _, h := range headers {
				if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
					w.Header().Set(
						textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(parts[0])),
						strings.TrimSpace(parts[1]),
					)
				}
			}
		}

		// Configurar Content-Type si está especificado
		if cRes.content_type != nil {
			w.Header().Set("Content-Type", C.GoString(cRes.content_type))
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}

		// Establecer código de estado
		statusCode := http.StatusOK
		if cRes.status_code != 0 {
			statusCode = int(cRes.status_code)
		}

		// Escribir cuerpo de respuesta si existe
		var body []byte
		if cRes.body != nil {
			body = []byte(C.GoString(cRes.body))
		}

		// Escribir respuesta
		w.WriteHeader(statusCode)
		if len(body) > 0 {
			w.Write(body)
		}
	})
}

//export GetAuthToken
func GetAuthToken(req *C.HttpRequest) *C.char {
    // Primero intentamos obtener el header de Authorization directamente
    authHeader := GetHeaderValue(req, C.CString("Authorization"))
    if authHeader == nil {
        return nil
    }
    defer C.free(unsafe.Pointer(authHeader))
    
    authValue := C.GoString(authHeader)
    
    // Manejar Bearer token
    if strings.HasPrefix(authValue, "Bearer ") {
        return C.CString(strings.TrimPrefix(authValue, "Bearer "))
    }
    
    // Manejar Basic auth
    if strings.HasPrefix(authValue, "Basic ") {
        // Decodificar el token Basic (usuario:contraseña en base64)
        encoded := strings.TrimPrefix(authValue, "Basic ")
        decoded, err := base64.StdEncoding.DecodeString(encoded)
        if err != nil {
            return nil
        }
        return C.CString(string(decoded))
    }
    
    // Si no es ninguno de los formatos conocidos, devolver el valor completo
    return C.CString(authValue)
}

// Función adicional para obtener solo el Bearer token (más específica)
//export GetBearerToken
func GetBearerToken(req *C.HttpRequest) *C.char {
    authHeader := GetHeaderValue(req, C.CString("Authorization"))
    if authHeader == nil {
        return nil
    }
    defer C.free(unsafe.Pointer(authHeader))
    
    authValue := C.GoString(authHeader)
    if strings.HasPrefix(authValue, "Bearer ") {
        return C.CString(strings.TrimPrefix(authValue, "Bearer "))
    }
    
    return nil
}

//export StartServer
func StartServer(port *C.char) {
	portStr := C.GoString(port)
	fmt.Printf("Starting server on port %s\n", portStr)
	go func() {
		if err := http.ListenAndServe(":"+portStr, nil); err != nil {
			panic(fmt.Sprintf("Failed to start server: %v", err))
		}
	}()
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

func main() {}