/*#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "http.h"

int main() {
    // Configurar expiración a 1 segundo
    SetDefaultTokenExpiry(1);
    
    // Generar token
    char* token = GenerateToken();
    printf("Token generado: %s\n", token);

    //InvalidateToken(token);
    
    // Verificar token inmediatamente
    int valid = ValidateToken(token);
    printf("Token válido? %s\n", valid == 1 ? "Sí" : valid == 0 ? "No existe" : "Expirado");
    printf("Tiempo restante: %.3f segundos\n", GetTokenRemainingTime(token));
    
    // Esperar 0.5 segundos
    usleep(500000);
    printf("\nDespués de 0.5s:\n");
    valid = ValidateToken(token);
    printf("Token válido? %s\n", valid == 1 ? "Sí" : valid == 0 ? "No existe" : "Expirado");
    printf("Tiempo restante: %.3f segundos\n", GetTokenRemainingTime(token));
    
    // Esperar otros 0.6 segundos (total 1.1s)
    usleep(600000);
    printf("\nDespués de 1.1s:\n");
    valid = ValidateToken(token);
    printf("Token válido? %s\n", valid == 1 ? "Sí" : valid == 0 ? "No existe" : "Expirado");
    printf("Tiempo restante: %.3f segundos\n", GetTokenRemainingTime(token));
    
    // Liberar memoria
    free(token);
    
    return 0;
}*/



#include <stdio.h>
#include "http.h"
#include <unistd.h>

Response my_handler(Request req) {
    printf("%s",GetHeaderValue(req, "demo"));
    return CreateResponse(200,"{\"status\":\"success\"}");
}

int main() {
    // Registrar handler y iniciar servidor
    RegisterHandler("/api", my_handler);
    StartServer("8123", 0, NULL, NULL);
    
    // Mantener el programa en ejecución
    getchar();
    /*while(1) {
        sleep(1);
    }*/
    
    return 0;
}