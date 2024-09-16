package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

var rateLimit int
var apiLimiter *rate.Limiter

type testRequest struct {
	IP string `json:"ip"`
}

func checkIpAddress(w http.ResponseWriter, r *http.Request) {
	if !apiLimiter.Allow() {
		http.Error(w, fmt.Sprintf("Exceeded Rate Limit of %d requests per minute", rateLimit), http.StatusTooManyRequests)
		return
	}

	var requestBody testRequest
	var err error

	err = decodeJson(r, &requestBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if requestBody.IP == "" {
		http.Error(w, "ip field is missing or empty", http.StatusBadRequest)
		return
	}

	response := fmt.Sprintf("IP address: %v", requestBody.IP)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))

}

func decodeJson(r *http.Request, requestBody interface{}) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var err error

	defer r.Body.Close()

	err = decoder.Decode(&requestBody)
	if err != nil {
		if _, ok := err.(*json.SyntaxError); ok {
			return err
		}
		if unmarshalError, ok := err.(*json.UnmarshalTypeError); ok {
			return fmt.Errorf("Invalid type for field '%s': expected %s, received %s", unmarshalError.Field, unmarshalError.Type, unmarshalError.Value)
		}

		return err
	}

	return nil
}

func handleRequests(reateLimit int) {
	smux := http.NewServeMux()

	smux.HandleFunc("GET /api/v1/test", checkIpAddress)

	server := &http.Server{
		Addr:         "localhost:5000",
		Handler:      smux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err.Error())
	}
}

func main() {
	// default rate limit : 5 requests per second
	flag.IntVar(&rateLimit, "rate_limit", 5, "Rate limit for processing requests")
	flag.Parse()

	apiLimiter = rate.NewLimiter(rate.Every(time.Minute/5), 5)

	handleRequests(rateLimit)
}
