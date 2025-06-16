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
    char* username = GetUsername(req);
    char* password = GetPassword(req);
    char* token = GetBearerToken(req);
    char* path = GetPath(req);
    char* method = GetMethod(req);
    char* ip = GetClientIP(req);
    char* user_agent = GetHeaderValue(req, "User-Agent");
    char* body = GetBody(req);

    printf("------------ HEADER ------------\n");
    printf("User: %s\n", username);
    printf("Password: %s\n", password);
    printf("Token: %s\n", token);
    printf("Path: %s\n", path);
    printf("Método: %s\n", method);
    printf("IP Cliente: %s\n", ip);
    printf("User Agent: %s\n", user_agent);
    printf("------------ BODY -------------\n");
    printf("%s\n", body);

    char* respuesta = "{\"mensaje\": \"Hola desde C!\"}";

    //las que se obtienen con GetHeaderValue se deben liberar
    free(user_agent);

    return CreateResponse(200, respuesta);
}

int main() {
    // Registrar el handler en la ruta /hola
    RegisterHandler("/hola", basic_handler);

    // Iniciar el servidor en el puerto 5000 sin TLS y sin filtro de IP
    StartServer("8080", 0, NULL, NULL);
    // Iniciar servidor HTTPS con certificados
    //StartServer("443", 0, "./server.crt", "./server.key");

    // Mantener el programa en ejecución
    printf("Servidor escuchando en http://localhost:5000\n");
    while (1) {
        sleep(1);
    }

    return 0;
}
```

---

### 🧪 Ejemplo de Auntenticacion Basica y Token 

```C
#include <stdio.h>
#include <unistd.h>
#include "http.h"

Response token_handler(Request req) {
    if (strcmp(GetBearerToken(req), "123") == 0) {
        return CreateResponse(200, "{\"message\":\"Valid token\"}");
    } else {
        return CreateResponse(403, "{\"error\":\"Invalid token\"}");
    }
}

Response login_handler(Request req) {
    if (strcmp(GetUsername(req), "admin") == 0 && strcmp(GetPassword(req), "secret") == 0) {
        CreateResponse(200, "{\"token\":\"123\"}");
    } else {
        return CreateResponse(401, "{\"error\":\"Invalid credentials\"}");
    }
}

int main() {
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
