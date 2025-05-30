package main

/*
#include <stdlib.h>
#include <string.h>

typedef struct {
    char** data;
    int count;
} StringArray;
*/
import "C"
import (
	"strings"
	"unsafe"
)

// Exportar funciones para C

// Concat concatena dos strings y devuelve un nuevo string
//export Concat
func Concat(s1, s2 *C.char) *C.char {
	goS1 := C.GoString(s1)
	goS2 := C.GoString(s2)
	result := goS1 + goS2
	return C.CString(result)
}

// ConcatAll concatena todas las strings pasadas como argumentos
//export ConcatAll
func ConcatAll(strs **C.char, count C.int) *C.char {
	// Convertir el array de C a slice de Go
	length := int(count)
	tmpslice := (*[1 << 30]*C.char)(unsafe.Pointer(strs))[:length:length]
	
	goStrs := make([]string, length)
	for i, s := range tmpslice {
		goStrs[i] = C.GoString(s)
	}
	
	result := strings.Join(goStrs, "")
	return C.CString(result)
}

// ToUpperCase convierte un string a mayúsculas
//export ToUpperCase
func ToUpperCase(s *C.char) *C.char {
	goStr := C.GoString(s)
	return C.CString(strings.ToUpper(goStr))
}

// ToLowerCase convierte un string a minúsculas
//export ToLowerCase
func ToLowerCase(s *C.char) *C.char {
	goStr := C.GoString(s)
	return C.CString(strings.ToLower(goStr))
}

// Trim elimina espacios en blanco al inicio y final
//export Trim
func Trim(s *C.char) *C.char {
	goStr := C.GoString(s)
	return C.CString(strings.TrimSpace(goStr))
}

// ReplaceAll reemplaza todas las ocurrencias de old por new
//export ReplaceAll
func ReplaceAll(s, old, new *C.char) *C.char {
	goStr := C.GoString(s)
	goOld := C.GoString(old)
	goNew := C.GoString(new)
	return C.CString(strings.ReplaceAll(goStr, goOld, goNew))
}

//export NewStringArray
func NewStringArray(size C.int) *C.StringArray {
    goSize := int(size)
    
    // Allocate memory for the char* array
    cArray := make([]*C.char, goSize)
    
    // Convert Go slice to C array
    cArrayPtr := (**C.char)(C.malloc(C.size_t(goSize) * C.size_t(unsafe.Sizeof((*C.char)(nil)))))
    for i := range cArray {
        *(*unsafe.Pointer)(unsafe.Pointer(uintptr(unsafe.Pointer(cArrayPtr)) + uintptr(i)*unsafe.Sizeof((*C.char)(nil)))) = 
            unsafe.Pointer(cArray[i])
    }
    
    // Create and configure the StringArray structure
    cStrArray := (*C.StringArray)(C.malloc(C.size_t(unsafe.Sizeof(C.StringArray{}))))
    cStrArray.data = cArrayPtr
    cStrArray.count = C.int(goSize)
    
    return cStrArray
}

// SetStringArrayValue asigna un valor a una posición del array
//export SetStringArrayValue
func SetStringArrayValue(arr *C.StringArray, index C.int, value *C.char) {
	goIndex := int(index)
	
	if arr == nil || goIndex < 0 || goIndex >= int(arr.count) {
		return // Índice fuera de rango o array inválido
	}
	
	// Liberamos el string anterior si existía
	ptr := *(**C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(arr.data)) + uintptr(goIndex)*unsafe.Sizeof((*C.char)(nil))))
	if ptr != nil {
		C.free(unsafe.Pointer(ptr))
	}
	
	// Asignamos el nuevo valor
	*(**C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(arr.data)) + uintptr(goIndex)*unsafe.Sizeof((*C.char)(nil)))) = C.CString(C.GoString(value))
}

// GetStringArrayValue obtiene un valor del array
//export GetStringArrayValue
func GetStringArrayValue(arr *C.StringArray, index C.int) *C.char {
	goIndex := int(index)
	
	if arr == nil || goIndex < 0 || goIndex >= int(arr.count) {
		return nil // Índice fuera de rango o array inválido
	}
	
	return *(**C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(arr.data)) + uintptr(goIndex)*unsafe.Sizeof((*C.char)(nil))))
}

// GetStringArraySize obtiene el tamaño del array
//export GetStringArraySize
func GetStringArraySize(arr *C.StringArray) C.int {
	if arr == nil {
		return 0
	}
	return arr.count
}

// JoinStringArray une los elementos del array con un separador
//export JoinStringArray
func JoinStringArray(arr *C.StringArray, delimiter *C.char) *C.char {
	if arr == nil {
		return C.CString("")
	}
	
	goDelimiter := C.GoString(delimiter)
	var builder strings.Builder
	
	for i := 0; i < int(arr.count); i++ {
		if i > 0 {
			builder.WriteString(goDelimiter)
		}
		ptr := *(**C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(arr.data)) + uintptr(i)*unsafe.Sizeof((*C.char)(nil))))
		if ptr != nil {
			builder.WriteString(C.GoString(ptr))
		}
	}
	
	return C.CString(builder.String())
}

// FreeStringArray libera la memoria de un StringArray
//export FreeStringArray
func FreeStringArray(arr *C.StringArray) {
	if arr == nil {
		return
	}
	
	// Liberamos cada string individual
	for i := 0; i < int(arr.count); i++ {
		ptr := *(**C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(arr.data)) + uintptr(i)*unsafe.Sizeof((*C.char)(nil))))
		if ptr != nil {
			C.free(unsafe.Pointer(ptr))
		}
	}
	
	// Liberamos el array de punteros
	C.free(unsafe.Pointer(arr.data))
	
	// Liberamos la estructura
	C.free(unsafe.Pointer(arr))
}

// FreeString libera memoria asignada por funciones que retornan *C.char
//export FreeString
func FreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

func main() {} // Necesario para buildear como plugin