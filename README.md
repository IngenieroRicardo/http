# HTTP
Librería C para crear WebService JSON con soporte de autenticación JWT, filtrado por IP y cabeceras de seguridad avanzadas.  
Compilada usando: `go build -o http.dll -buildmode=c-shared http.go`

---

### 📥 Descargar la librería

| Linux | Windows |
| --- | --- |
| `wget https://github.com/IngenieroRicardo/http/releases/download/3.1/http.so` | `Invoke-WebRequest https://github.com/IngenieroRicardo/http/releases/download/3.1/http.dll -OutFile ./http.dll` |
| `wget https://github.com/IngenieroRicardo/http/releases/download/3.1/http.h` | `Invoke-WebRequest https://github.com/IngenieroRicardo/http/releases/download/3.1/http.h -OutFile ./http.h` |

---

### 🛠️ Compilar

| Linux | Windows |
| --- | --- |
| `gcc -o main.bin main.c ./http.so` | `gcc -o main.exe main.c ./http.dll` |
| `x86_64-w64-mingw32-gcc -o main.exe main.c ./http.dll` |  |

---

### 🧪 Ejemplo básico

```c
#include <stdio.h>
#include <unistd.h>
#include "http.h"

Response basic_handler(Request req) {
    char* username = GetUsername(req);
    char* password = GetPassword(req);
    char* token = GetBearerToken(req);
    char* path = GetPath(req);
    char* method = GetMethod(req);
    char* ip = GetClientIP(req);
    char* host = GetHost(req);
    char* user_agent = GetHeaderValue(req, "User-Agent");
    char* body = GetBody(req);

    printf("------------ HEADER ------------\n");
    printf("User: %s\n", username);
    printf("Password: %s\n", password);
    printf("Token: %s\n", token);
    printf("Path: %s\n", path);
    printf("Método: %s\n", method);
    printf("IP Cliente: %s\n", ip);
    printf("Host: %s\n", host);
    printf("User Agent: %s\n", user_agent);
    printf("------------ BODY -------------\n");
    printf("%s\n", body);

    char* respuesta = "{\"mensaje\": \"Hola desde C!\"}";

    // Liberar memoria de las cadenas obtenidas (excepto aquellas pasadas a CreateResponse)
    free(username);
    free(password);
    free(token);
    free(path);
    free(method);
    free(ip);
    free(host);
    free(user_agent);
    free(body);

    return CreateResponse(200, respuesta);
}

int main() {
    RegisterHandler("/hola", basic_handler);
    StartServer("8080", 0, NULL, NULL);
    printf("Servidor escuchando en http://localhost:8080\n");
    while (1) sleep(1);
    return 0;
}
```

---

### 🔐 Ejemplo de autenticación básica con credenciales

```c
#include <stdio.h>
#include <unistd.h>
#include "http.h"

Response login_handler(Request req) {
    char* user = GetUsername(req);
    char* pass = GetPassword(req);

    if (ValidateCredential(user, pass) == 1) {
        // Generar token JWT válido por 1 hora (3600 segundos)
        char* token = GenerateToken(1001, 3600);
        char response[256];
        snprintf(response, sizeof(response), "{\"token\":%s}", token);
        Response res = CreateResponse(200, response);
        free(token);
        free(user);
        free(pass);
        return res;
    } else {
        free(user);
        free(pass);
        return CreateResponse(401, "{\"error\":\"Invalid credentials\"}");
    }
}

int main() {
    // Cargar credenciales: usuario:contraseña separadas por comas
    LoadCredentials("admin:secret,user1:pass123");
    RegisterHandler("/api/login", login_handler);
    StartServer("8080", 0, NULL, NULL);
    while (1) sleep(1);
    return 0;
}
```

---

### 🎫 Ejemplo de autenticación JWT

```c
#include <stdio.h>
#include <unistd.h>
#include "http.h"

Response protected_handler(Request req) {
    char* token = GetBearerToken(req);
    if (ValidateToken(token) == 1) {
        free(token);
        return CreateResponse(200, "{\"message\":\"Acceso autorizado\"}");
    } else {
        free(token);
        return CreateResponse(403, "{\"error\":\"Token inválido o expirado\"}");
    }
}

int main() {
    RegisterHandler("/api/protected", protected_handler);
    StartServer("8080", 0, NULL, NULL);
    while (1) sleep(1);
    return 0;
}
```

---

### 🧪 Ejemplo de bloqueo mediante WhiteList y BlackList

```c
#include <stdio.h>
#include <unistd.h>
#include "http.h"

Response ip_check_handler(Request req) {
    char* client_ip = GetClientIP(req);
    char* response_body = malloc(100);
    snprintf(response_body, 100, "{\"message\":\"%s success\"}", client_ip);
    Response res = CreateResponse(200, response_body);
    free(response_body);
    free(client_ip);
    return res;
}

int main() {
    // Cargar listas de IPs
    LoadWhitelist("192.168.1.100,192.168.1.101");
    LoadBlacklist("10.0.0.5,10.0.0.6");

    // Agregar IPs dinámicamente
    AddToWhitelist("127.0.0.1");
    AddToBlacklist("192.168.1.102");

    RegisterHandler("/check-ip", ip_check_handler);

    // Iniciar servidor con filtro de IP habilitado (enableFilter = 1)
    StartServer("8080", 1, NULL, NULL);

    while (1) sleep(1);
    return 0;
}
```

---

## 📚 Documentación de la API

### Funciones Principales
- `void RegisterHandler(char* path, HttpHandler handler)`  
  Registra un manejador para la ruta especificada.
- `void StartServer(char* port, int enableFilter, char* certFile, char* keyFile)`  
  Inicia el servidor HTTP. Si `enableFilter` es `1`, se activa el filtro de IP basado en whitelist/blacklist.  
  Para HTTPS, proporciona los archivos de certificado y clave.

### Obtención de Datos de la Petición
Todas estas funciones devuelven una cadena que debe ser liberada con `free()` cuando ya no sea necesaria.

| Función | Descripción |
|---------|-------------|
| `char* GetMethod(Request r)` | Método HTTP (GET, POST, etc.) |
| `char* GetPath(Request r)` | Ruta solicitada |
| `char* GetBody(Request r)` | Cuerpo de la petición (JSON) |
| `char* GetClientIP(Request r)` | Dirección IP del cliente (teniendo en cuenta X-Forwarded-For) |
| `char* GetHost(Request r)` | Host de la petición |
| `char* GetHeaders(Request r)` | Todos los headers en formato JSON |
| `char* GetHeaderValue(Request r, char* key)` | Valor de un header específico (búsqueda insensible a mayúsculas) |
| `char* GetUsername(Request r)` | Usuario de autenticación básica (si existe) |
| `char* GetPassword(Request r)` | Contraseña de autenticación básica (si existe) |
| `char* GetBearerToken(Request r)` | Token Bearer (si existe) |

### Autenticación y Credenciales
| Función | Descripción |
|---------|-------------|
| `int LoadCredentials(char* credenciales)` | Carga credenciales en formato "usuario:contraseña,usuario2:contraseña2". Devuelve `1` si éxito, `0` si error. |
| `int ValidateCredential(char* usuario, char* contrasena)` | Verifica si las credenciales coinciden con las cargadas. Devuelve `1` si válidas, `0` si no. |
| `char* GenerateToken(int userid, long long expiration)` | Genera un token JWT firmado con el ID de usuario y tiempo de expiración en segundos. Devuelve una cadena JSON con el token. La cadena debe ser liberada con `free()`. |
| `int ValidateToken(char* tokenString)` | Valida un token JWT. Devuelve `1` si es válido y no ha expirado, `0` en caso contrario. |

### Gestión de IPs (Whitelist/Blacklist)
| Función | Descripción |
|---------|-------------|
| `int AddToWhitelist(char* ip)` | Agrega una IP a la whitelist. Elimina de blacklist si existía. |
| `int RemoveFromWhitelist(char* ip)` | Elimina una IP de la whitelist. |
| `int AddToBlacklist(char* ip)` | Agrega una IP a la blacklist. Elimina de whitelist si existía. |
| `int RemoveFromBlacklist(char* ip)` | Elimina una IP de la blacklist. |
| `int IsWhitelisted(char* ip)` | Verifica si una IP está en la whitelist. |
| `int IsBlacklisted(char* ip)` | Verifica si una IP está en la blacklist. |
| `void LoadWhitelist(char* ips)` | Carga una lista de IPs separadas por comas en la whitelist (reemplaza la actual). |
| `void LoadBlacklist(char* ips)` | Carga una lista de IPs separadas por comas en la blacklist (reemplaza la actual). |

### Creación de Respuestas
- `Response CreateResponse(int statusCode, char* body)`  
  Crea una respuesta HTTP con el código de estado y cuerpo (JSON). El cuerpo se copia internamente, por lo que la cadena original puede ser liberada después de la llamada.

### Seguridad Incorporada
Cada petición recibe automáticamente las siguientes cabeceras de seguridad:
- `Content-Security-Policy`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security` (si la conexión es HTTPS)

### ⚠️ Nota sobre memoria
Todas las funciones que devuelven `char*` asignan memoria con `malloc`. **Debes llamar a `free()`** sobre esas cadenas cuando ya no las necesites. La única excepción es cuando pasas una cadena a `CreateResponse`, ya que esta función la copia internamente y puedes liberar la original inmediatamente después. No liberes la cadena devuelta por `CreateResponse` (la respuesta será liberada automáticamente por la librería).

---
