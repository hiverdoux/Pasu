package main

/*
#include <libproc.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func pidPathCgo(pid int) (string, error) {
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	n, err := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if n <= 0 {
		return "", fmt.Errorf("proc_pidpath 실패: %v", err)
	}
	return string(buf[:n]), nil
}
