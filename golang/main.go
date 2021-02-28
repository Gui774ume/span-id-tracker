//+build linux

package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"

	muxtrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer/erpc"
)

func handler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello World!\n"))
}

func openVulnHandler(w http.ResponseWriter, r *http.Request) {
	_, err := os.Create("/tmp/secrets")
	if err != nil {
		w.Write([]byte(fmt.Sprintf("couldn't open /tmp/secrets: %v\n", err)))
	} else {
		w.Write([]byte("vuln triggered !\n"))
	}
}

func execVulnHandler(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("id").Output()
	if err != nil {
		w.Write([]byte(fmt.Sprintf("couldn't execute `id`: %v\n", err)))
	}
	w.Write(out)
}

func spanAlteringAttempt(w http.ResponseWriter, r *http.Request) {
	// create a new span, without using the tracer to emulate an attacker making an ioctl syscall manually
	c, err := erpc.NewERPCClient(erpc.GoroutineTracker)
	if err != nil {
		w.Write([]byte(fmt.Sprintf("failed to create new eRPC client: %v\n", err)))
	}
	if err := c.SendNewSpan(erpc.Goid(), 1234,5678); err != nil {
		w.Write([]byte(fmt.Sprintf("couldn't send fake span: %v\n", err)))
	}
	_, _ = os.Create("/tmp/secrets")
	w.Write([]byte("fake span sent!\n"))
}

func main() {
	tracer.Start(
		tracer.WithService("span.tracker"),
		tracer.WithERPCMode(erpc.GoroutineTracker),
	)
	defer tracer.Stop()

	mux := muxtrace.NewRouter()
	mux.HandleFunc("/hello", handler)
	mux.HandleFunc("/vuln/open", openVulnHandler)
	mux.HandleFunc("/vuln/exec", execVulnHandler)
	mux.HandleFunc("/vuln/span_altering_attempt", spanAlteringAttempt)
	fmt.Println("listening on http://localhost:8080")
	http.ListenAndServe(":8080", mux)
}
