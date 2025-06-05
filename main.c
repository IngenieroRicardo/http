#include <stdio.h>
#include "http.h"
#include <unistd.h>

Response my_handler(Request req) {
    char* demo = GetHeaderValue(req, "demo");
    printf("%s", demo);
    free(demo);
    return CreateResponse(200,"{\"status\":\"success\"}");
}

int main() {
    // Registrar handler y iniciar servidor
    RegisterHandler("/api", my_handler);
    StartServer("8123", 0, NULL, NULL);
    
    // Mantener el programa en ejecución
    getchar();
    
    
    return 0;
}