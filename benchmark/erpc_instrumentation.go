package benchmark

import (
	_ "unsafe"
)

//go:linkname _ddog_runtime_execute runtime._ddog_runtime_execute
func _ddog_runtime_execute(goID int64, tid uint64) {
	return
}
