package main

/*
#include <stdlib.h> // Para free()
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

// FreeString libera memoria asignada por funciones que retornan *C.char
//export FreeString
func FreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

func main() {} // Necesario para buildear como plugin