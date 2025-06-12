# HTTP
Libreria C para crear WebService JSON.  
Compilada usando: `go build -o http.dll -buildmode=c-shared http.go`

---

### 📥 Descargar la librería

| Linux | Windows |
| --- | --- |
| `wget https://github.com/IngenieroRicardo/http/releases/download/2.0/http.so` | `Invoke-WebRequest https://github.com/IngenieroRicardo/http/releases/download/2.0/http.dll -OutFile ./http.dll` |
| `wget https://github.com/IngenieroRicardo/http/releases/download/2.0/http.h` | `Invoke-WebRequest https://github.com/IngenieroRicardo/http/releases/download/2.0/http.h -OutFile ./http.h` |

---

### 🛠️ Compilar

| Linux | Windows |
| --- | --- |
| `gcc -o main.bin main.c ./http.so` | `gcc -o main.exe main.c ./http.dll` |
| `x86_64-w64-mingw32-gcc -o main.exe main.c ./http.dll` |  |

---

### 🧪 Ejemplo básico

```C
#include <stdio.h>
#include <unistd.h>
#include "http.h"

Response basic_handler(Request req) {
    char* method = GetMethod(req);
    char* path = GetPath(req);
    char* user_agent = GetHeaderValue(req, "User-Agent");
    char* body = GetBody(req);

    printf("\nreceived: %s %s %s\n %s\n", method, path, user_agent, body);
    
    // Crear una respuesta simple
    return CreateResponse(200, "{\"message\":\"Hola Mundo C handler!\"}");
}

int main() {
    // Registrar un manejador para la ruta "/hola"
    RegisterHandler("/hola", basic_handler);
    
    // Iniciar el servidor en el puerto 8080 sin filtro de IP
    StartServer("8080", 0, NULL, NULL);
    // Iniciar servidor HTTPS con certificados
    //StartServer("443", 0, "./server.crt", "./server.key");
    
    // Mantener el programa en ejecución
    while(1) {
        sleep(1);
    }
    
    return 0;
}
```

---

### 🧪 Ejemplo de Auntenticacion Basica y Token 

```C
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "http.h"

Response token_handler(Request req) {
    char* token = GetBearerToken(req);
    
    int token_status = ValidateToken(token);
    if (token_status == 1) {
        return CreateResponse(200, "{\"message\":\"Valid token\"}");
    } else {
        return CreateResponse(403, "{\"error\":\"Invalid token\"}");
    }
    
}

Response login_handler(Request req) {
    char* username = GetUsername(req);
    char* password = GetPassword(req);
    
    // Verificación de credenciales (simplificada)
    if (strcmp(username, "admin") == 0 && strcmp(password, "secret") == 0) {
        // Generar nuevo token
        char* token = GenerateToken();
        
        // Crear el JSON de respuesta manualmente
        char* response_body = malloc(strlen(token) + 20); // Espacio suficiente
        sprintf(response_body, "{\"token\":\"%s\"}", token);
        
        Response res = CreateResponse(200, response_body);
        
        // Liberar memoria
        free(response_body);
        free(token);
        return res;
    }
    
    return CreateResponse(401, "{\"error\":\"Invalid credentials\"}");
}

int main() {
    // Configurar duración del token (1 hora)
    SetDefaultTokenExpiry(3600);
    
    RegisterHandler("/api/login", login_handler);
    RegisterHandler("/api/protected", token_handler);
    
    StartServer("8080", 0, NULL, NULL);
    
    while(1) {
        sleep(1);
    }
    
    return 0;
}

```

---

### 🧪 Ejemplo de bloqueo mediante WhiteList y BlackList

```C
#include <stdio.h>
#include <unistd.h>
#include "http.h"

Response ip_check_handler(Request req) {
    char* client_ip = GetClientIP(req);
    char* response_body = malloc(100);
    
    sprintf(response_body, "{\"message\":\"%s success\"}", client_ip);
    
    Response res = CreateResponse(200, response_body);
    free(response_body); // Liberar la memoria asignada
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
    
    // Iniciar servidor con filtro de IP habilitado
    StartServer("8080", 1, NULL, NULL);
    
    while(1) {
        sleep(1);
    }
    
    return 0;
}
```

---

## 📚 Documentación de la API

### Funciones Principales
- `void RegisterHandler(char* path, HttpHandler handler)`: Registrar un manejador de ruta
- `void StartServer(char* port, int enableFilter, char* certFile, char* keyFile)`: Iniciar el servidor HTTP

#### Obtención de Valores
- `char* GetMethod(Request r)`: Obtener método HTTP
- `char* GetPath(Request r)`: Obtener ruta solicitada
- `char* GetBody(Request r)`: Obtener cuerpo de la petición
- `char* GetClientIP(Request r)`: Obtener IP del cliente
- `char* GetHeaders(Request r)`: Obtener todos los headers
- `char* GetHeaderValue(Request r, *char clave)`: Obtener valor de header específico
- `char* GetUsername(Request r)`: Obtener usuario de basic auth
- `char* GetPassword(Request r)`: Obtener contraseña de basic auth
- `char* GetBearerToken(Request r)`: Obtener token bearer

#### Gestión de IPs
- `int AddToWhitelist(char* ip)`
- `int RemoveFromWhitelist(char* ip)`
- `int AddToBlacklist(char* ip)`
- `int RemoveFromBlacklist(char* ip)`
- `int IsWhitelisted(char* ip)`
- `int IsBlacklisted(char* ip)`
- `void LoadWhitelist(char* ips)`: Cargar lista de IPs separadas por comas
- `void LoadBlacklist(char* ips)`: Cargar lista de IPs separadas por comas

#### Gestión de Tokens
- `char* GenerateToken()`: Crear nuevo token
- `int ValidateToken(char* token)`: Validar token (1=válido, 0=inválido, -1=expirado)
- `void InvalidateToken(char* token)`: Invalidar token
- `void SetTokenSecretKey(char* key)`: Establecer clave secreta para tokens
- `void SetDefaultTokenExpiry(int seconds)`: Establecer TTL por defecto
- `char* GenerateToken()`: Obtener info del token (recordar usar FreeTokenInfo)
- `void FreeTokenInfo(TokenInfo* info)`: Liberar memoria de la info del token
- `int CleanExpiredTokens()`: Eliminar tokens expirados
