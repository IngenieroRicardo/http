#include <stdio.h>
#include <stdlib.h>
#include "BASICOS.h"

int main() {
    // Inicializar (si es necesario)
    
    // Ejemplo de Concat
    char* result1 = Concat("Hola ", "mundo!");
    printf("Concatenación simple: %s\n", result1);
    FreeString(result1);
    
    // Ejemplo de ConcatAll
    char* strings[] = {"Go", " y ", "C ", "juntos!"};
    char* result2 = ConcatAll((char**)strings, 4);
    printf("Concatenación múltiple: %s\n", result2);
    FreeString(result2);
    
    // Ejemplo de ToUpperCase
    char* upper = ToUpperCase("esto es una prueba");
    printf("Mayúsculas: %s\n", upper);
    FreeString(upper);
    
    // Ejemplo de ReplaceAll
    char* replaced = ReplaceAll("El gato come pescado", "gato", "perro");
    printf("Reemplazo: %s\n", replaced);
    FreeString(replaced);
    
    return 0;
}