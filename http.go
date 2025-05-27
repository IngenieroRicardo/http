package main

/*
#include <stdlib.h>

typedef char* (*HttpHandler)(char* method, char* path, char* body, char* client_ip, char* headers);

static char* call_handler(HttpHandler handler, char* method, char* path, char* body, char* client_ip, char* headers) {
    return handler(method, path, body, client_ip, headers);
}
*/
import "C"
import (
	"io/ioutil"
	"net/http"
	"strings"
	"unsafe"

	"net/url"
	"fmt"
	"mime"
	"mime/multipart"
)

func getClientIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-IP")
	}
	if ip == "" {
		ip = strings.Split(r.RemoteAddr, ":")[0]
	}
	return ip
}

func getHeadersString(r *http.Request) string {
	var headers strings.Builder
	for name, values := range r.Header {
		for _, value := range values {
			headers.WriteString(name)
			headers.WriteString(": ")
			headers.WriteString(value)
			headers.WriteString("\n")
		}
	}
	return headers.String()
}

//export RegisterHandler
func RegisterHandler(path *C.char, handler C.HttpHandler) {
	pathStr := C.GoString(path)
	http.HandleFunc(pathStr, func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		defer r.Body.Close()

		cMethod := C.CString(r.Method)
		cPath := C.CString(r.URL.Path)
		cBody := C.CString(string(body))
		cClientIP := C.CString(getClientIP(r))
		cHeaders := C.CString(getHeadersString(r))


		data, err:=GetVariableFromFormData(string(body), r.Header.Get("Content-Type"), "b")
		if err==nil{
			fmt.Println("DATA:",data,r.Header.Get("Content-Type"))
		} else {
			fmt.Println("NOO:",data,r.Header.Get("Content-Type"))
		}
		
		defer C.free(unsafe.Pointer(cMethod))
		defer C.free(unsafe.Pointer(cPath))
		defer C.free(unsafe.Pointer(cBody))
		defer C.free(unsafe.Pointer(cClientIP))
		defer C.free(unsafe.Pointer(cHeaders))

		cResponse := C.call_handler(handler, cMethod, cPath, cBody, cClientIP, cHeaders)
		defer C.free(unsafe.Pointer(cResponse))

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(C.GoString(cResponse)))
	})
}

//export StartServer
func StartServer(port *C.char) {
	portStr := C.GoString(port)
	go func() {
		if err := http.ListenAndServe(":"+portStr, nil); err != nil {
			panic(err)
		}
	}()
}








// GetVariableFromFormData extrae una variable de form-data (x-www-form-urlencoded o multipart/form-data)
// Retorna el valor como string o un error si no existe.
func GetVariableFromFormData(sBody, contentType, variableName string) (string, error) {
	// Parsear el Content-Type para ver si es multipart
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", fmt.Errorf("invalid Content-Type: %v", err)
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		// Procesar como multipart/form-data
		boundary, ok := params["boundary"]
		if !ok {
			return "", fmt.Errorf("no boundary in Content-Type for multipart form")
		}

		reader := multipart.NewReader(strings.NewReader(sBody), boundary)
		form, err := reader.ReadForm(32 << 20) // 32MB max memory
		if err != nil {
			return "", fmt.Errorf("error reading multipart form: %v", err)
		}

		if val := form.Value[variableName]; len(val) > 0 {
			return val[0], nil
		}
		return "", fmt.Errorf("variable '%s' not found in multipart form", variableName)
	} else {
		// Procesar como x-www-form-urlencoded
		values, err := url.ParseQuery(sBody)
		if err != nil {
			return "", fmt.Errorf("error parsing form data: %v", err)
		}

		if val := values.Get(variableName); val != "" {
			return val, nil
		}
		return "", fmt.Errorf("variable '%s' not found in form data", variableName)
	}
}

func main() {}
