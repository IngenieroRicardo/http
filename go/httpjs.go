// file httpjs.go

// +build js

package http

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"fmt"
	"syscall/js"
	"time"
	"net/url"
	"encoding/hex"
    "math/rand"
    "github.com/golang-jwt/jwt/v5"
)

var secretKey = []byte("https://github.com/IngenieroRicardo/http")

var (
    credentials   = make(map[string]string)
    credentialsMu sync.RWMutex // para acceso concurrente seguro (opcional, pero buena práctica)
)

var filterEnabled bool


func jsValueToInterface(v js.Value) interface{} {
	switch v.Type() {
	case js.TypeString:
		return v.String()
	case js.TypeNumber:
		// Los números en JS siempre son float64
		return v.Float()
	case js.TypeBoolean:
		return v.Bool()
	case js.TypeNull, js.TypeUndefined:
		return nil
	case js.TypeObject:
		// Detectar si es un array (tiene longitud >0 o propiedad "length" numérica)
		// Nota: En JS, los arrays también son objetos, pero tienen longitud.
		if v.Length() > 0 || v.Get("length").Type() == js.TypeNumber {
			length := v.Length()
			slice := make([]interface{}, length)
			for i := 0; i < length; i++ {
				slice[i] = jsValueToInterface(v.Index(i))
			}
			return slice
		}
		// Es un objeto plano: convertir a map[string]interface{}
		// Obtenemos las keys usando Object.keys(v)
		keys := js.Global().Get("Object").Call("keys", v)
		mapResult := make(map[string]interface{}, keys.Length())
		for i := 0; i < keys.Length(); i++ {
			key := keys.Index(i).String()
			mapResult[key] = jsValueToInterface(v.Get(key))
		}
		return mapResult
	case js.TypeFunction:
		// No convertimos funciones; podrías devolver la propia v si lo necesitas
		// pero en código interpretado no podrías usarla sin importar syscall/js.
		// Por simplicidad, devolvemos nil.
		return nil
	default:
		return nil
	}
}

func NewResponse(body interface{}, init map[string]interface{}) js.Value {
    jsInit := js.ValueOf(init)
    return js.Global().Get("Response").New(body, jsInit)
}

type HttpRequest struct {
    data map[string]interface{}
}

func (r HttpRequest) GetPath() string {
    if urlStr, ok := r.data["url"].(string); ok {
        u, err := url.Parse(urlStr)
        if err == nil {
            return u.Path
        }
    }
    return ""
}

func (r HttpRequest) GetMethod() string {
    if method, ok := r.data["method"].(string); ok {
        return method
    }
    return "GET"
}

func (r HttpRequest) GetHeaderValue(key string) string {
    headers, ok := r.data["headers"].(map[string]interface{})
    if !ok {
        return ""
    }
    lowerKey := strings.ToLower(key)
    for k, v := range headers {
        if strings.ToLower(k) == lowerKey {
            if s, ok := v.(string); ok {
                return s
            }
        }
    }
    return ""
}

func (r HttpRequest) GetHeaders() string {
    headers, ok := r.data["headers"].(map[string]interface{})
    if !ok {
        return ""
    }
    var sb strings.Builder
    for k, v := range headers {
        sb.WriteString(fmt.Sprintf("%s: %v\n", k, v))
    }
    return sb.String()
}

func (r HttpRequest) GetBody() string {
    if body, ok := r.data["body"].(string); ok {
        return body
    }
    return ""
}

func (r HttpRequest) GetClientIP() string {
    return "127.0.0.1"
}

func (r HttpRequest) GetUsername() string {
    auth := r.GetHeaderValue("Authorization")
    if strings.HasPrefix(auth, "Basic ") {
        encoded := strings.TrimPrefix(auth, "Basic ")
        decoded, err := base64.StdEncoding.DecodeString(encoded)
        if err != nil {
            return ""
        }
        parts := strings.SplitN(string(decoded), ":", 2)
        if len(parts) > 0 {
            return parts[0]
        }
    }
    return ""
}

func (r HttpRequest) GetPassword() string {
    auth := r.GetHeaderValue("Authorization")
    if strings.HasPrefix(auth, "Basic ") {
        encoded := strings.TrimPrefix(auth, "Basic ")
        decoded, err := base64.StdEncoding.DecodeString(encoded)
        if err != nil {
            return ""
        }
        parts := strings.SplitN(string(decoded), ":", 2)
        if len(parts) > 1 {
            return parts[1]
        }
    }
    return ""
}

func (r HttpRequest) GetBearerToken() string {
    auth := r.GetHeaderValue("Authorization")
    if strings.HasPrefix(auth, "Bearer ") {
        return strings.TrimPrefix(auth, "Bearer ")
    }
    return ""
}

// HttpResponse representa una respuesta HTTP.
type HttpResponse struct {
    status  int
    body    string
    headers map[string]string
}

// CreateResponse crea una nueva respuesta con código de estado y cuerpo.
// Opcionalmente se pueden pasar cabeceras como un mapa adicional.
func CreateResponse(status int, body string) HttpResponse {
    headers := map[string]string{
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none';",
        "X-Content-Type-Options":  "nosniff",
        "Referrer-Policy":          "strict-origin-when-cross-origin",
        "Permissions-Policy":       "camera=(), microphone=(), geolocation=(), payment=()",
        "X-Frame-Options":          "DENY",
        "X-XSS-Protection":         "1; mode=block",
        "Content-Type":             "application/json", // valor por defecto
    }
    // Nota: Strict-Transport-Security no se incluye automáticamente
    // porque requiere que la conexión sea HTTPS. Si se necesita,
    // el usuario puede añadirla con AddHeader.
    return HttpResponse{
        status:  status,
        body:    body,
        headers: headers,
    }
}

// toJSValue convierte la respuesta a un objeto js.Value (Response) para el enrutador.
func (r HttpResponse) toJSValue() js.Value {
    init := map[string]interface{}{
        "status": r.status,
    }
    if len(r.headers) > 0 {
        h := make(map[string]interface{})
        for k, v := range r.headers {
            h[k] = v
        }
        init["headers"] = h
    }
    return NewResponse(r.body, init)
}


// StartServer (expuesto como http.StartServer) inicia el servidor registrando las rutas.
// Los parámetros (puerto, backlog, cert, key) se ignoran en este entorno.
func StartServer(port string, enableFilter int, certFile, keyFile string) {
    // Validar que el puerto coincida con el puerto real del servidor
    location := js.Global().Get("location")
    protocol := location.Get("protocol").String()
    currentPort := location.Get("port").String()
    
    // Si el puerto no está explícito, asignar según protocolo
    if currentPort == "" {
        if protocol == "https:" {
            currentPort = "443"
        } else {
            currentPort = "80"
        }
    }

    // Solo validar si tenemos un puerto actual y el usuario no pasó una cadena vacía
    if currentPort != "" && port != "" && port != currentPort {
        js.Global().Get("console").Call("log", "solo puedes usar el puerto: "+ currentPort)
    	panic("Puerto invalido: "+port)
    }

    if enableFilter != 0 {
        filterEnabled = true
    } else {
        filterEnabled = false
    }
    ListenAndServe()
}


var defaultServer = &server{
    routes:   make(map[string]js.Func),
    handlers: []js.Func{},
}

type server struct {
    routes   map[string]js.Func
    handlers []js.Func
}
// HandleFunc registra un handler para una ruta.
// El handler debe tener la firma func(js.Value) js.Value, donde el argumento es el Request de JS
// y el valor de retorno debe ser un objeto Response (o una Promise que resuelva a Response).
func HandleFunc(path string, h func([]interface{}) interface{}) {
    if err := registerRouteWithSW(path); err != nil {
        panic("Error al iniciar el servidor: " + err.Error())
    }

    wrapper := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
        req := args[0]
        method := req.Get("method").String()

        // --- Para métodos que no son OPTIONS, procesamos normalmente ---
        promise := js.Global().Get("Promise").New(js.FuncOf(func(this js.Value, promiseArgs []js.Value) interface{} {
            resolve := promiseArgs[0]
            reject := promiseArgs[1]

            // Leer el cuerpo como texto (asíncrono)
            textPromise := req.Call("text")
            textPromise.Call("then", js.FuncOf(func(this js.Value, thenArgs []js.Value) interface{} {
                bodyText := thenArgs[0].String()

                // Construir mapa base
                reqMap := make(map[string]interface{})
                if filterEnabled {
                    tempReq := HttpRequest{data: reqMap}
                    clientIP := tempReq.GetClientIP()
                    if !IsIPAllowed(clientIP) {
                        // Si no está permitida, devolvemos 403
                        errResp := CreateResponse(403, `Forbidden`).toJSValue()
                        resolve.Invoke(errResp)
                        return nil
                    }
                }
                reqMap["method"] = method
                reqMap["url"] = req.Get("url").String()

                // Extraer cabeceras de forma segura
                headers := make(map[string]interface{})
                jsHeaders := req.Get("headers")
                if !jsHeaders.IsUndefined() && !jsHeaders.IsNull() {
                    cb := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
                        value := args[0].String()
                        key := args[1].String()
                        headers[key] = value
                        return nil
                    })
                    defer cb.Release()
                    jsHeaders.Call("forEach", cb)
                }
                reqMap["headers"] = headers
                reqMap["body"] = bodyText

                // Llamar al handler original (el del usuario)
                var result interface{}
                func() {
                    defer func() {
                        if r := recover(); r != nil {
                            result = CreateResponse(500, "Internal Server Error: handler panic").toJSValue()
                        }
                    }()
                    result = h([]interface{}{reqMap})
                }()

                // Convertir el resultado a js.Value
                var respJS js.Value
                switch v := result.(type) {
                case *HttpResponse:
                    respJS = v.toJSValue()
                case js.Value:
                    respJS = v
                default:
                    respJS = js.ValueOf(result)
                }

                // Añadir cabeceras CORS a la respuesta (opcional pero recomendado)
                if !respJS.IsUndefined() && !respJS.IsNull() {
                    // Agregar Access-Control-Allow-Origin a la respuesta
                    respJS.Get("headers").Call("set", "Access-Control-Allow-Origin", "*")
                }

                resolve.Invoke(respJS)
                return nil
            }), js.FuncOf(func(this js.Value, catchArgs []js.Value) interface{} {
                errMsg := catchArgs[0].Get("message").String()
                reject.Invoke(js.Global().Get("Error").New("Error al leer cuerpo: " + errMsg))
                return nil
            }))
            return nil
        }))
        return promise
    })

    defaultServer.handlers = append(defaultServer.handlers, wrapper)
    defaultServer.routes[path] = wrapper
}



// RegisterHandler registra un manejador con la nueva firma amigable.
// Automáticamente valida que las peticiones con cuerpo tengan Content-Type application/json
// y que el cuerpo sea JSON válido.
func RegisterHandler(path string, handler func(HttpRequest) HttpResponse) {
    wrapped := func(args []interface{}) interface{} {
        // Verificar que recibimos datos de la petición
        if len(args) == 0 {
            return CreateResponse(500, "Internal Server Error: no request data").toJSValue()
        }
        reqMap, ok := args[0].(map[string]interface{})
        if !ok || reqMap == nil {
            return CreateResponse(500, "Internal Server Error: invalid request format").toJSValue()
        }
        req := HttpRequest{data: reqMap}

        // --- VALIDACIÓN DE JSON PARA PETICIONES CON CUERPO ---
        method := req.GetMethod()
        body := req.GetBody()

        if method != "GET" && method != "HEAD" && len(body) > 0 {
            // Verificar Content-Type
            contentType := req.GetHeaderValue("Content-Type")
            if !strings.Contains(strings.ToLower(contentType), "application/json") {
                return CreateResponse(400, "Invalid JSON format").toJSValue()
            }
            // Verificar que el cuerpo sea JSON válido
            var js json.RawMessage
            if err := json.Unmarshal([]byte(body), &js); err != nil {
                return CreateResponse(400, "Invalid JSON format").toJSValue()
            }
        }
        // ----------------------------------------------------

        // Llamar al handler del usuario
        resp := handler(req)
        return resp.toJSValue()
    }
    HandleFunc(path, wrapped)
}


// ListenAndServe registra todas las rutas en el enrutador JavaScript (window.registerRoute)
// y mantiene los handlers activos.
func ListenAndServe() {
    registerRoute := js.Global().Get("registerRoute")
    if registerRoute.IsUndefined() {
        js.Global().Get("console").Call("log", "registerRoute no está definida. ¿Olvidaste incluir serviceworker.js?")
        return
    }
    for path, handler := range defaultServer.routes {
        registerRoute.Invoke(path, handler)
    }
}



func generateID() string {
    b := make([]byte, 16)
    _, err := rand.Read(b)
    if err != nil {
        return time.Now().Format("20060102150405") + "-" + randomString(8)
    }
    return hex.EncodeToString(b)
}

func randomString(n int) string {
    const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
    b := make([]byte, n)
    for i := range b {
        b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
        time.Sleep(1)
    }
    return string(b)
}

func (r HttpRequest) GetHost() string {
    // Intentar obtener de la cabecera Host
    host := r.GetHeaderValue("Host")
    if host != "" {
        return host
    }
    // Si no, extraer de la URL
    if urlStr, ok := r.data["url"].(string); ok {
        u, err := url.Parse(urlStr)
        if err == nil && u.Host != "" {
            return u.Host
        }
    }
    return ""
}

func GenerateToken(userid int, expiration int64) string {
    claims := jwt.MapClaims{
        "user_id": userid,
        "exp":     time.Now().Add(time.Second * time.Duration(expiration)).Unix(),
        "iat":     time.Now().Unix(),
        "iss":     "http-api",
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(secretKey)
    if err != nil {
        return `{"error":"No se pudo generar el token"}`
    }
    response := map[string]interface{}{
        "access_token": tokenString,
        "token_type":   "Bearer",
        "expires_in":   expiration,
    }
    jsonResponse, err := json.Marshal(response)
    if err != nil {
        return `{"error":"No se pudo generar el JSON"}`
    }
    return string(jsonResponse)
}

// ValidateToken valida un token JWT y devuelve true si es válido
func ValidateToken(tokenString string) bool {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Validar el método de firma
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("método de firma inesperado: %v", token.Header["alg"])
        }
        return secretKey, nil
    })
    if err != nil || !token.Valid {
        return false
    }
    return true
}


func LoadCredentials(credenciales string) bool {
    credentialsMu.Lock()
    defer credentialsMu.Unlock()

    // Limpiar credenciales previas
    credentials = make(map[string]string)

    pairs := strings.Split(credenciales, ",")
    for _, pair := range pairs {
        partes := strings.SplitN(pair, ":", 2)
        if len(partes) != 2 {
            return false // formato incorrecto
        }
        user := strings.TrimSpace(partes[0])
        pass := strings.TrimSpace(partes[1])
        if user == "" || pass == "" {
            return false
        }
        credentials[user] = pass
    }
    return true
}

// ValidateCredential verifica si un usuario y contraseña coinciden con alguna credencial cargada.
func ValidateCredential(usuario, contraseña string) bool {
    credentialsMu.RLock()
    defer credentialsMu.RUnlock()

    if storedPass, ok := credentials[usuario]; ok {
        return storedPass == contraseña
    }
    return false
}








func IsWhitelisted(ip string) bool {
    listMu.RLock()
    defer listMu.RUnlock()
    return whitelist[ip]
}
func IsBlacklisted(ip string) bool {
    listMu.RLock()
    defer listMu.RUnlock()
    return blacklist[ip]
}
func IsIPAllowed(ip string) bool {
    listMu.RLock()
    defer listMu.RUnlock()
    // Si hay whitelist, solo las que están en ella son permitidas
    if len(whitelist) > 0 {
        return whitelist[ip]
    }
    // Si no hay whitelist, se permite si no está en blacklist
    return !blacklist[ip]
}


var (
    whitelist   = make(map[string]bool)
    blacklist   = make(map[string]bool)
    listMu      sync.RWMutex
)

// Reemplaza cualquier whitelist anterior.
func LoadWhitelist(ips string) {
    listMu.Lock()
    defer listMu.Unlock()
    whitelist = make(map[string]bool)
    parts := strings.Split(ips, ",")
    for _, ip := range parts {
        ip = strings.TrimSpace(ip)
        if ip != "" {
            whitelist[ip] = true
        }
    }
}

// LoadBlacklist carga una lista de IPs bloqueadas desde un string separado por comas.
// Reemplaza cualquier blacklist anterior.
func LoadBlacklist(ips string) {
    listMu.Lock()
    defer listMu.Unlock()
    blacklist = make(map[string]bool)
    parts := strings.Split(ips, ",")
    for _, ip := range parts {
        ip = strings.TrimSpace(ip)
        if ip != "" {
            blacklist[ip] = true
        }
    }
}

// AddToWhitelist añade una IP a la whitelist.
func AddToWhitelist(ip string) {
    listMu.Lock()
    defer listMu.Unlock()
    if whitelist == nil {
        whitelist = make(map[string]bool)
    }
    whitelist[ip] = true
}

// AddToBlacklist añade una IP a la blacklist.
func AddToBlacklist(ip string) {
    listMu.Lock()
    defer listMu.Unlock()
    if blacklist == nil {
        blacklist = make(map[string]bool)
    }
    blacklist[ip] = true
}


// RemoveFromWhitelist elimina una IP de la whitelist.
// Retorna 1 si la IP existía y fue eliminada, 0 si no estaba.
func RemoveFromWhitelist(ip string) int {
    listMu.Lock()
    defer listMu.Unlock()
    if _, ok := whitelist[ip]; ok {
        delete(whitelist, ip)
        return 1
    }
    return 0
}

// RemoveFromBlacklist elimina una IP de la blacklist.
// Retorna 1 si la IP existía y fue eliminada, 0 si no estaba.
func RemoveFromBlacklist(ip string) int {
    listMu.Lock()
    defer listMu.Unlock()
    if _, ok := blacklist[ip]; ok {
        delete(blacklist, ip)
        return 1
    }
    return 0
}




func registerRouteWithSW(path string) error {
	if !strings.HasPrefix(path, "/api/") {
    	js.Global().Get("console").Call("log", "tus rutas solo pueden empezar con /api/")
    	panic("Ruta invalida: "+path)
	}

    maxAttempts := 5
    for attempt := 1; attempt <= maxAttempts; attempt++ {
        sw := js.Global().Get("navigator").Get("serviceWorker")
        if sw.IsUndefined() {
            time.Sleep(500 * time.Millisecond)
            continue
        }

        controller := sw.Get("controller")
        if controller.IsUndefined() {
            time.Sleep(1 * time.Second)
            continue
        }

        messageId := generateID()
        ch := make(chan map[string]interface{})
        done := make(chan struct{})

        handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
            event := args[0]
            data := event.Get("data")
            if data.IsUndefined() {
                return nil
            }
            if data.Get("type").String() == "ROUTE_REGISTERED" && data.Get("messageId").String() == messageId {
                resp := map[string]interface{}{
                    "overwritten": data.Get("overwritten").Bool(),
                    "path":        data.Get("path").String(),
                }
                select {
                case ch <- resp:
                case <-done:
                }
            }
            return nil
        })
        js.Global().Get("navigator").Get("serviceWorker").Call("addEventListener", "message", handler)

        msg := map[string]interface{}{
            "type":      "REGISTER_ROUTE",
            "path":      path,
            "messageId": messageId,
        }
        controller.Call("postMessage", js.ValueOf(msg))

        select {
        case resp := <-ch:
            js.Global().Get("navigator").Get("serviceWorker").Call("removeEventListener", "message", handler)
            handler.Release()
            close(done)

            if overwritten, ok := resp["overwritten"].(bool); ok && overwritten {
                return fmt.Errorf("ruta %s ya registrada", path)
            } else {
                return nil
            }

        case <-time.After(3 * time.Second):
            js.Global().Get("navigator").Get("serviceWorker").Call("removeEventListener", "message", handler)
            handler.Release()
            close(done)
            time.Sleep(1 * time.Second)
            continue
        }
    }
    return fmt.Errorf("no se pudo registrar la ruta %s después de varios intentos", path)
}


