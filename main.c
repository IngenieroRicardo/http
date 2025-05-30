#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "http.h"
#include "BASICOS.h"

// Función auxiliar para crear respuestas JSON de error
HttpResponse* create_error_response(int status, char* message) {
    HttpResponse* res = create_http_response();
    if (!res) return NULL;
    
    res->status_code = status;
    res->content_type = strdup("application/json");
    
    // Usamos Concat para crear el mensaje de error
    char* error_msg = message ? message : "Unknown error";
    char* error_part = Concat("{\"error\":\"", error_msg);
    if (!error_part) {
        free(res->content_type);
        free(res);
        return NULL;
    }
    
    char* body = Concat(error_part, "\"}");
    FreeString(error_part);
    
    if (!body) {
        free(res->content_type);
        free(res);
        return NULL;
    }
    
    res->body = body;
    return res;
}

HttpResponse* handle_root(HttpRequest* req) {
    if (!req) return create_error_response(500, "Internal Server Error");

    char* auth_token = GetAuthToken(req);
    if (auth_token != NULL) {
        printf("Token de autorización: %s\n", auth_token);
        free(auth_token);
    }
    
    // Obtener solo Bearer token
    char* bearer_token = GetBearerToken(req);
    if (bearer_token != NULL) {
        printf("Bearer token: %s\n", bearer_token);
        free(bearer_token);
    }

    
    printf("\n=== Nueva petición ===\n");
    printf("IP Cliente: %s\n", req->client_ip ? req->client_ip : "NULL");
    printf("Método: %s\n", req->method ? req->method : "NULL");
    printf("Path: %s\n", req->path ? req->path : "NULL");
    printf("Content-Type: %s\n", req->content_type ? req->content_type : "NULL");
    printf("Headers:\n%s\n", req->headers ? req->headers : "NULL");
    printf("Body: %s\n", req->body ? req->body : "NULL");
    
    HttpResponse* res = create_http_response();
    if (!res) return create_error_response(500, "Internal Server Error");
    
    res->status_code = 200;
    res->content_type = strdup("application/json");
    
    // Usamos ConcatAll para construir el JSON
    char* safe_client_ip = req->client_ip ? req->client_ip : "";
    char* safe_path = req->path ? req->path : "";
    char* safe_method = req->method ? req->method : "";
    
    char* parts[] = {
        "{\"status\":\"ok\",\"client_ip\":\"",
        safe_client_ip,
        "\",\"path\":\"",
        safe_path,
        "\",\"method\":\"",
        safe_method,
        "\"}"
    };
    
    char* response_body = ConcatAll(parts, 7);
    if (!response_body) {
        free(res->content_type);
        free(res);
        return create_error_response(500, "Internal Server Error");
    }
    
    res->body = response_body;
    return res;
}

HttpResponse* handle_form(HttpRequest* req) {
    if (!req) return create_error_response(500, "Internal Server Error");

    // Verificar que sea POST
    if (!req->method || strcmp(req->method, "POST") != 0) {
        return create_error_response(405, "Método no permitido");
    }

    // Verificar Content-Type
    if (!req->content_type || 
        (strstr(req->content_type, "application/x-www-form-urlencoded") == NULL && 
        strstr(req->content_type, "multipart/form-data") == NULL)) {
        return create_error_response(400, "Content-Type no soportado");
    }

    // Obtener valores del formulario
    char* nombre = GetFormValue(req, "nombre");
    char* email = GetFormValue(req, "email");
    char* file = GetFormValue(req, "file");
    char* cabeza = GetHeaderValue(req, "cabeza");
    
    if (!nombre || !email) {
        if (nombre) FreeString(nombre);
        if (email) FreeString(email);
        if (file) FreeString(file);
        if (cabeza) FreeString(cabeza);
        return create_error_response(400, "Faltan campos requeridos (nombre, email)");
    }

    // Crear respuesta
    HttpResponse* res = create_http_response();
    if (!res) {
        FreeString(nombre);
        FreeString(email);
        if (file) FreeString(file);
        if (cabeza) FreeString(cabeza);
        return create_error_response(500, "Internal Server Error");
    }
    
    res->status_code = 200;
    res->content_type = strdup("application/json");
    
    // Construir el JSON usando ConcatAll
    char* file_value = file ? file : "null";
    char* cabeza_value = cabeza ? cabeza : "null";
    
    char* parts[] = {
        "{\"status\":\"success\",\"data\":{\"nombre\":\"",
        nombre,
        "\",\"email\":\"",
        email,
        "\",\"file\":\"",
        file_value,
        "\",\"cabeza\":\"",
        cabeza_value,
        "\"}}"
    };
    
    char* response_body = ConcatAll(parts, 9);
    if (!response_body) {
        FreeString(nombre);
        FreeString(email);
        if (file) FreeString(file);
        if (cabeza) FreeString(cabeza);
        free(res->content_type);
        free(res);
        return create_error_response(500, "Internal Server Error");
    }
    
    res->body = response_body;

    // Liberar memoria
    FreeString(nombre);
    FreeString(email);
    if (file) FreeString(file);
    if (cabeza) FreeString(cabeza);
    
    return res;
}

HttpResponse* handle_hola(HttpRequest* req) {
    if (!req) return create_error_response(500, "Internal Server Error");
    
    printf("Hola desde IP: %s\n", req->client_ip ? req->client_ip : "NULL");
    
    // Ejemplo de GetFormValue con query parameters
    char* nombre = GetFormValue(req, "nombre");
    if (!nombre) {
        nombre = strdup("visitante");
    }
    
    HttpResponse* res = create_http_response();
    if (!res) {
        FreeString(nombre);
        return create_error_response(500, "Internal Server Error");
    }
    
    res->status_code = 200;
    res->content_type = strdup("application/json");
    
    // Construir respuesta usando ConcatAll
    char* safe_client_ip = req->client_ip ? req->client_ip : "";
    char* safe_method = req->method ? req->method : "";
    
    char* parts[] = {
        "{\"message\":\"¡Hola ",
        nombre,
        " desde C!\",\"your_ip\":\"",
        safe_client_ip,
        "\",\"method\":\"",
        safe_method,
        "\"}"
    };
    
    char* response_body = ConcatAll(parts, 7);
    FreeString(nombre);
    
    if (!response_body) {
        free(res->content_type);
        free(res);
        return create_error_response(500, "Internal Server Error");
    }
    
    res->body = response_body;
    return res;
}

int main() {
    // Registrar handlers para diferentes rutas
    RegisterHandler("/", handle_root);
    RegisterHandler("/hola", handle_hola);
    RegisterHandler("/form", handle_form);
    
    // Iniciar el servidor en el puerto 8012
    //StartServer("8012");
    StartServerWithIPFilter("8012", 1);
    // Cargar múltiples IPs a whitelist
    /*LoadWhitelist("192.100.1.73, 192.168.1.102, 10.0.0.20");
    AddToWhitelist("10.0.0.15");// Agregar IPs a whitelist*/
    // Cargar múltiples IPs a blacklist
    LoadBlacklist("192.100.1.72, 192.168.1.102, 10.0.0.20");
    AddToBlacklist("10.0.0.15");// Agregar IP a blacklist

    // Construir mensajes usando BASICOS
    char* parts[] = {"Servidor ejecutándose en http://localhost:", "8012"};
    char* msg1 = ConcatAll(parts, 2);
    if (msg1) {
        printf("%s\n", msg1);
        FreeString(msg1);
    } else {
        printf("Servidor ejecutándose en http://localhost:8012\n");
    }
    
    printf("Endpoints disponibles:\n");
    printf("  GET /       - Muestra información de la petición\n");
    printf("  GET /hola   - Saludo simple (opcional: ?nombre=TuNombre)\n");
    printf("  POST /form  - Procesa formularios (campos: nombre, email)\n");
    printf("\nPresiona Enter para detener el servidor...\n");
    
    getchar(); // Mantener el programa en ejecución
    
    return 0;
}