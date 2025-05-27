#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "http.h"

char* handle_root(char* method, char* path, char* body, char* client_ip, char* headers) {
    printf("\n=== Nueva petición ===\n");
    printf("IP Cliente: %s\n", client_ip);
    printf("Método: %s\n", method);
    printf("Path: %s\n", path);
    printf("Headers:\n%s\n", headers);
    printf("Body: %s\n", body);
    
    char* response = malloc(512);
    snprintf(response, 512, 
        "{\"status\":\"ok\",\"client_ip\":\"%s\",\"path\":\"%s\"}", 
        client_ip, path);
    return response;
}

char* handle_hola(char* method, char* path, char* body, char* client_ip, char* headers) {
    printf("Hola desde IP: %s\n", client_ip);
    char* response = malloc(128);
    strcpy(response, "{\"message\":\"¡Hola desde C!\",\"your_ip\":\"");
    strcat(response, client_ip);
    strcat(response, "\"}");
    return response;
}

int main() {
    RegisterHandler("/", handle_root);
    RegisterHandler("/hola", handle_hola);
    
    StartServer("8012");
    
    printf("Server running at http://localhost:8012\n");
    printf("Press Enter to stop...\n");
    getchar();
    
    return 0;
}
