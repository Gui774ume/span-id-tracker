package benchmark

import (
	"bytes"
	"fmt"
	"github.com/Gui774ume/span-id-tracker/benchmark/erpc"
	"io"
	"os"
	"path"
	"testing"
	"time"

	"github.com/DataDog/ebpf/manager"
)

type TracedStruct struct {
	goID int64
}

//go:noinline
func TracedFunc(elem *TracedStruct) int64 {
	_ = time.Now()
	return elem.goID
}

//func BenchmarkSpanCreation(b *testing.B) {
//	tracer.Start(
//		tracer.WithService("span.tracker"),
//	)
//	for i := 0; i < b.N; i++ {
//		span := tracer.StartSpan("web.request", tracer.ResourceName("/posts"))
//		time.Sleep(1 * time.Millisecond)
//		span.Finish()
//
//	}
//	tracer.Stop()
//}

func BenchmarkFunctionCall(b *testing.B) {
	a := TracedStruct{goID: 42}
	for i := 0; i < b.N; i++ {
		_ = TracedFunc(&a)
	}
}

var eClient *erpc.ERPC

func TracedFuncWithERPC(elem *TracedStruct) int64 {
	_ = time.Now()
	_ = eClient.SendNewSpan(erpc.Goid(), 1234, 5678)
	return elem.goID
}

func BenchmarkFunctionCallWithERPCNoKprobe(b *testing.B) {
	var err error
	eClient, err = erpc.NewERPCClient(erpc.GoroutineTracker)
	if err != nil {
		b.Fatal(err)
	}
	a := TracedStruct{goID: 42}
	for i := 0; i < b.N; i++ {
		_ = TracedFuncWithERPC(&a)
	}
}

func setupKprobe() {
	m = &manager.Manager{}

	probe := &manager.Probe{
		UID:        "12345678910",
		Section:    "kprobe/do_vfs_ioctl",
	}
	m.Probes = []*manager.Probe{
		probe,
	}

	options := manager.Options{
		ActivatedProbes: []manager.ProbesSelector{
			&manager.ProbeSelector{
				ProbeIdentificationPair: probe.GetIdentificationPair(),
			},
		},
	}

	if err := m.InitWithOptions(recoverAssets(), options); err != nil {
		fmt.Println(err)
	}

	if err := m.Start(); err != nil {
		fmt.Println(err)
	}
}

func BenchmarkFunctionCallWithERPCKprobe(b *testing.B) {
	a := TracedStruct{goID: 42}
	setupKprobe()
	for i := 0; i < b.N; i++ {
		_ = TracedFuncWithERPC(&a)
	}
	teardown()
}

func recoverAssets() io.ReaderAt {
	buf, err := Asset("/probe.o")
	if err != nil {
		fmt.Println(err)
	}
	return bytes.NewReader(buf)
}

var m *manager.Manager

func setupUprobe(section string) {
	m = &manager.Manager{}

	p, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}

	probe := &manager.Probe{
		UID:        "12345678910",
		Section:    section,
		MatchFuncName: "github.com/Gui774ume/span-id-tracker/benchmark.TracedFunc",
		BinaryPath: path.Join(p, "bin/benchmark"),
	}
	m.Probes = []*manager.Probe{
		probe,
	}

	options := manager.Options{
		ActivatedProbes: []manager.ProbesSelector{
			&manager.ProbeSelector{
				ProbeIdentificationPair: probe.GetIdentificationPair(),
			},
		},
	}

	if err := m.InitWithOptions(recoverAssets(), options); err != nil {
		fmt.Println(err)
	}

	coroutineCtxMap, _, err := m.GetMap("coroutine_ctx")
	if err != nil {
		fmt.Println(err)
	}
	if err := coroutineCtxMap.Put(uint32(0), [231]byte{}); err != nil {
		fmt.Println(err)
	}

	if err := m.Start(); err != nil {
		fmt.Println(err)
	}
}

func teardown() {
	_ = m.Stop(manager.CleanAll)
}

func BenchmarkFunctionWithEmptyUprobe(b *testing.B) {
	setupUprobe("uprobe/empty_probe")
	a := TracedStruct{goID: 42}
	for i := 0; i < b.N; i++ {
		_ = TracedFunc(&a)
	}
	teardown()
}

func BenchmarkFunctionWithComplexUprobe(b *testing.B) {
	setupUprobe("uprobe/complex_probe")
	a := TracedStruct{goID: 42}
	for i := 0; i < b.N; i++ {
		_ = TracedFunc(&a)
	}
	teardown()
}

func TracedFuncWithMemorySegment(elem *TracedStruct) int64 {
	_ = time.Now()
	eClient.HandleRuntimeExecuteEvent(erpc.Goid(), erpc.Mid())
	return elem.goID
}

func BenchmarkFunctionWithRuntimeInstrumentation(b *testing.B) {
	var err error
	eClient, err = erpc.NewERPCClient(erpc.MemorySegment)
	if err != nil {
		b.Fatal(err)
	}
	a := TracedStruct{goID: 42}
	for i := 0; i < b.N; i++ {
		_ = TracedFuncWithMemorySegment(&a)
	}
}
