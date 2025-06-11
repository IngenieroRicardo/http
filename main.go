package main

import (
	"fmt"
	"time"
	http "github.com/IngenieroRicardo/http/go"
)

func ip_check_handler(req http.HttpRequest) http.HttpResponse {
	client_ip := req.GetClientIP()
	response_body := fmt.Sprintf("{\"message\":\"%s success\"}", client_ip)

	res := http.CreateResponse(200, response_body)
	
	return res
}

func main() {
	// Cargar listas de IPs
    http.LoadWhitelist("192.168.1.100,192.168.1.101")
    http.LoadBlacklist("10.0.0.5,10.0.0.6")
    
    // Agregar IPs dinámicamente
    http.AddToWhitelist("127.0.0.1")
    http.AddToBlacklist("192.168.1.102")
    
    http.RegisterHandler("/check-ip", ip_check_handler)
    
    // Iniciar servidor con filtro de IP habilitado
    http.StartServer("8080", 1, "", "");
	    
	for {
		time.Sleep(1 * time.Second)
	}
}











/*package main

import (
	"fmt"
	"time"
	http "github.com/IngenieroRicardo/http/go"
)

func token_handler(req http.HttpRequest) http.HttpResponse {
	token := req.GetBearerToken()

	token_status := http.ValidateToken(token)
    if (token_status == 1) {
        return http.CreateResponse(200, "{\"message\":\"Valid token\"}");
    } else {
        return http.CreateResponse(403, "{\"error\":\"Invalid token\"}");
    }
}

func login_handler(req http.HttpRequest) http.HttpResponse {
	username := req.GetUsername()
	password := req.GetPassword()

	// Verificación de credenciales (simplificada)
    if username == "admin" && password == "secret" {
        // Generar nuevo token
        token := http.GenerateToken()
        
        // Crear el JSON de respuesta manualmente
        response_body := fmt.Sprintf("{\"token\":\"%s\"}", token)
        
        res := http.CreateResponse(200, response_body);
        
        return res;
    }
	    
	return http.CreateResponse(200, `{"error":"Invalid credentials"}`)
}

func main() {
	// Configurar duración del token (1 hora)
	http.SetDefaultTokenExpiry(3600);
	
	http.RegisterHandler("/api/login", login_handler)
	http.RegisterHandler("/api/protected", token_handler)
	
	http.StartServer("8080", 0, "", "")
	
	for {
		time.Sleep(1 * time.Second)
	}
}*/






/*package main

import (
	"fmt"
	"time"
	http "github.com/IngenieroRicardo/http/go"
)

func basic_handler(req http.HttpRequest) http.HttpResponse {
	method := req.GetMethod()
	path := req.GetPath()
	userAgent := req.GetHeaderValue("User-Agent")
	body := req.GetBody()

	fmt.Printf("\nreceived: %s %s %s\n %s\n", method, path, userAgent, body)
	
	// Crear una respuesta simple
	return http.CreateResponse(200, `{"message":"Hola Mundo Go handler!"}`)
}

func main() {
	// Registrar un manejador para la ruta "/hola"
	http.RegisterHandler("/", basic_handler)
	
	// Iniciar el servidor en el puerto 8080 sin filtro de IP
	http.StartServer("8080", 0, "", "")
	// Iniciar servidor HTTPS con certificados
	//StartServer("443", 0, "./server.crt", "./server.key");

	// Mantener el programa en ejecución
	for {
		time.Sleep(1 * time.Second)
	}
}
*/
