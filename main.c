/*#include <stdio.h>
#include <unistd.h>
#include "http.h"

Response secure_handler(Request req) {
    return CreateResponse(200, "{\"message\":\"Secure connection established\"}");
}

int main() {
    RegisterHandler("/secure-data", secure_handler);
    
    // Iniciar servidor HTTPS con certificados
    StartServer("443", 0, "server.crt", "server.key");
    
    while(1) {
        sleep(1);
    }
    
    return 0;
}*/














/*#include <stdio.h>
#include <unistd.h>
#include "http.h"

Response echo_handler(Request req) {
    // Obtener información de la solicitud
    const char* method = GetMethod(req);
    const char* path = GetPath(req);
    const char* body = GetBody(req);
    const char* user_agent = GetHeaderValue(req, "User-Agent");
    
    // Construir respuesta con los datos recibidos
    char response[1024];
    snprintf(response, sizeof(response), 
        "{\"method\":\"%s\", \"path\":\"%s\", \"user_agent\":\"%s\", \"body\":%s}",
        method, path, 
        user_agent ? user_agent : "null",
        body ? body : "null");
    
    return CreateResponse(200, response);
}

int main() {
    RegisterHandler("/echo", echo_handler);
    StartServer("8123", 0, NULL, NULL);
    
    while(1) {
        sleep(1);
    }
    
    return 0;
}*/













/*#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
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
    StartServer("8123", 1, NULL, NULL);
    
    while(1) {
        sleep(1);
    }
    
    return 0;
}*/












/*#include <stdio.h>
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
    
    StartServer("8123", 0, NULL, NULL);
    
    while(1) {
        sleep(1);
    }
    
    return 0;
}*/
















/*#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "http.h"

Response auth_handler(Request req) {
    char* username = GetUsername(req);
    char* password = GetPassword(req);
    
    // Verificación simple de credenciales (en producción usar algo más seguro)
    if (strcmp(username, "admin") == 0 && strcmp(password, "secret") == 0) {
        return CreateResponse(200, "{\"message\":\"Welcome admin!\"}");
    }
    
    return CreateResponse(403, "{\"error\":\"Invalid credentials\"}");
}

int main() {
    RegisterHandler("/secure", auth_handler);
    StartServer("8123", 0, NULL, NULL);
    
    while(1) {
        sleep(1);
    }
    
    return 0;
}*/


/*#include <stdio.h>
#include <unistd.h>
#include "http.h"

Response basic_handler(Request req) {
    printf("Request received: %s %s\n", GetMethod(req), GetPath(req));
    
    // Crear una respuesta simple
    return CreateResponse(200, "{\"message\":\"Hello from C handler!\"}");
}

int main() {
    // Registrar un manejador para la ruta "/hello"
    RegisterHandler("/hello", basic_handler);
    
    // Iniciar el servidor en el puerto 8080 sin filtro de IP
    StartServer("8123", 0, NULL, NULL);
    
    // Mantener el programa en ejecución
    while(1) {
        sleep(1);
    }
    
    return 0;
}*/