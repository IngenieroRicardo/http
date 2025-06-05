# HTTP
Libreria C para crear WebService JSON.
Compilada usando: `go build -o HTTP.dll -buildmode=c-shared HTTP.go`

---

### 📥 Descargar la librería

| Linux | Windows |
| --- | --- |
| `wget https://github.com/IngenieroRicardo/HTTP/releases/download/1.0/HTTP.so` | `Invoke-WebRequest https://github.com/IngenieroRicardo/HTTP/releases/download/1.0/HTTP.dll -OutFile ./HTTP.dll` |
| `wget https://github.com/IngenieroRicardo/HTTP/releases/download/1.0/HTTP.h` | `Invoke-WebRequest https://github.com/IngenieroRicardo/HTTP/releases/download/1.0/HTTP.h -OutFile ./HTTP.h` |

---

### 🛠️ Compilar

| Linux | Windows |
| --- | --- |
| `gcc -o main.bin main.c ./HTTP.so` | `gcc -o main.exe main.c ./HTTP.dll` |
| `x86_64-w64-mingw32-gcc -o main.exe main.c ./HTTP.dll` |  |

---

### 🧪 Ejemplo básico

```C
#include <stdio.h>
#include <unistd.h>
#include "HTTP.h"

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
    
    // Mantener el programa en ejecución
    while(1) {
        sleep(1);
    }
    
    return 0;
}
```

---

### 🧪 Ejemplo de Autenticacion Basica

```C
#include <stdio.h>
#include <unistd.h>
#include "HTTP.h"

Response auth_handler(Request req) {
    char* username = GetUsername(req);
    char* password = GetPassword(req);
    
    // Verificación simple de credenciales (en producción usar algo más seguro)
    if (strcmp(username, "admin") == 0 && strcmp(password, "secret") == 0) {
        return CreateResponse(200, "{\"message\":\"Bienvenido admin!\"}");
    }
    
    return CreateResponse(403, "{\"error\":\"Invalid credentials\"}");
}

int main() {
    RegisterHandler("/seguro", auth_handler);
    StartServer("8080", 0, NULL, NULL);
    
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
#include "HTTP.h"

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

#### Manejo Básico de HTTP
- `HTTPResult ParseHTTP(const char* HTTP_str)`: Analiza una cadena HTTP
- `int IsValidHTTP(const char* HTTP_str)`: Verifica si una cadena es HTTP válido

#### Obtención de Valores
- `HTTPResult GetHTTPValue(const char* HTTP_str, const char* key)`: Obtiene valor por clave
- `HTTPResult GetHTTPValueByPath(const char* HTTP_str, const char* path)`: Obtiene valor por ruta
- `HTTPResult GetArrayLength(const char* HTTP_str)`: Obtiene longitud de array
- `HTTPResult GetArrayItem(const char* HTTP_str, int index)`: Obtiene elemento de array

#### Construcción/Modificación
- `HTTPResult CreateEmptyHTTP()`: Crea objeto HTTP vacío
- `HTTPResult CreateEmptyArray()`: Crea array HTTP vacío
- `HTTPResult AddStringToHTTP(const char* HTTP_str, const char* key, const char* value)`
- `HTTPResult AddNumberToHTTP(const char* HTTP_str, const char* key, double value)`
- `HTTPResult AddBooleanToHTTP(const char* HTTP_str, const char* key, int value)`
- `HTTPResult AddHTTPToHTTP(const char* parent_HTTP, const char* key, const char* child_HTTP)`
- `HTTPResult AddItemToArray(const char* HTTP_array, const char* item)`
- `HTTPResult RemoveKeyFromHTTP(const char* HTTP_str, const char* key)`
- `HTTPResult RemoveItemFromArray(const char* HTTP_array, int index)`
- `HTTPResult MergeHTTP(const char* HTTP1, const char* HTTP2)`: Combina dos HTTPs

#### Utilidades
- `void FreeHTTPResult(HTTPResult result)`: Libera memoria de resultados
- `void FreeHTTPArrayResult(HTTPArrayResult result)`: Libera memoria de arrays

### Estructuras
```c
typedef struct {
    char* value;      // Valor obtenido
    int is_valid;     // 1 si es válido, 0 si hay error
    char* error;      // Mensaje de error (si lo hay)
} HTTPResult;

typedef struct {
    char** items;     // Array de elementos
    int count;        // Número de elementos
    int is_valid;     // 1 si es válido, 0 si hay error
    char* error;      // Mensaje de error (si lo hay)
} HTTPArrayResult;
```
