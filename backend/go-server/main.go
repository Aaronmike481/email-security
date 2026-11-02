package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time" 

	"github.com/YuminosukeSato/pyproc/pkg/pyproc"
)

var pool *pyproc.Pool

func main() {
	var err error
	pool, err = pyproc.NewPool(pyproc.PoolOptions{
		Config: pyproc.PoolConfig{Workers: 2, MaxInFlight: 10},
		WorkerConfig: pyproc.WorkerConfig{
			SocketPath:   "/tmp/email.sock",
			PythonExec:   "python3",
			WorkerScript: "../worker.py",
			StartTimeout: 30 * time.Second,
		},
	}, nil)
	if err != nil { log.Fatal(err) }
	pool.Start(context.Background())
	defer pool.Shutdown(context.Background())

	http.HandleFunc("/email-audit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")

		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)

		var output map[string]interface{}
		if err := pool.Call(context.Background(), "email_audit", req, &output); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(output)
	})

	log.Println("Go server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}