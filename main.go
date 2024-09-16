package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var rateLimit int
var apiLimiter *rate.Limiter
var rateLimiter *RateLimiter
var remoteUrl string
var remoteDomain string

type testRequest struct {
	IP string `json:"ip"`
}

type testResponse struct {
	IpMatched bool   `json:"ip_matched"`
	Message   string `json:"message"`
}

// ----------- Rate Limiter --------------

type RateLimiter struct {
	RateLimit int
	Interval  time.Duration
	Requests  int
	Mutex     sync.Mutex
	Ticker    *time.Ticker
}

func NewRateLimiter(maxRequests int, interval time.Duration) *RateLimiter {
	rl := &RateLimiter{
		RateLimit: maxRequests,
		Interval:  interval,
		Ticker:    time.NewTicker(interval),
	}
	go rl.resetRequests()
	return rl
}

func (rl *RateLimiter) resetRequests() {
	for range rl.Ticker.C {
		rl.Mutex.Lock()
		rl.Requests = 0
		rl.Mutex.Unlock()
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.Mutex.Lock()
	defer rl.Mutex.Unlock()
	if rl.Requests < rl.RateLimit {
		rl.Requests++
		return true
	}
	return false
}

// ----------- Http Requests Helpers --------------

func SendGetRequest(url string) (data map[string]interface{}, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	if err = json.Unmarshal(body, &data); err != nil {
		return
	}

	return
}

// ----------- Handler Functions --------------

func checkIpAddress(w http.ResponseWriter, r *http.Request) {
	// Block OUR api to receive only X requests per minute
	// if !apiLimiter.Allow() {
	// 	http.Error(w, fmt.Sprintf("Exceeded Rate Limit of %d requests per minute", rateLimit), http.StatusTooManyRequests)
	// 	return
	// }

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

	ipMatched, err := checkIpMatch(requestBody.IP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	responseTxt, err, httpErrorCode := getCheckIpAdrdressResponse(requestBody.IP, ipMatched)
	if err != nil {
		http.Error(w, err.Error(), httpErrorCode)
		return
	}

	resonseObj := testResponse{
		IpMatched: ipMatched,
		Message:   responseTxt,
	}

	w.Header().Set("Content-Type", "application/json")

	jsonResponse, err := json.Marshal(resonseObj)
	if err != nil {
		http.Error(w, "Failed to marshal response JSON", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)

}

// ----------- Helper Functions --------------

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

func getDomainFromUrl(providedUrl string) (string, error) {
	urlParsed, err := url.Parse(providedUrl)
	if err != nil {
		return "", fmt.Errorf("error parsing url provided")
	}

	return urlParsed.Host, nil
}

func nslookup(domain string) ([]string, error) {
	ips, err := net.LookupHost(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup domain '%s': %w", domain, err)
	}
	return ips, nil
}

func checkIpMatch(ip string) (bool, error) {
	domainIps, err := nslookup(remoteDomain)
	if err != nil {
		return false, fmt.Errorf("error fetching ip of remote api domain")
	}

	ipMatched := false

	for _, domainIp := range domainIps {
		if domainIp == ip {
			ipMatched = true
			break
		}
	}
	return ipMatched, nil
}

func getCheckIpAdrdressResponse(ip string, ipMatched bool) (string, error, int) {
	response := fmt.Sprintf("Remote api doesn't have ip %s", ip)

	if ipMatched {
		if !rateLimiter.Allow() {
			return "", fmt.Errorf("Rate limit of %d requests per minute exceeded!", rateLimit), http.StatusTooManyRequests
		}

		remoteApiResponse, err := SendGetRequest(remoteUrl + "/json")
		if err != nil {
			return "", fmt.Errorf("error retreiving data form ip %s. %s", ip, err.Error()), http.StatusInternalServerError
		}

		val, ok := remoteApiResponse["value"]
		if !ok {
			return "", fmt.Errorf("Error with value received from ip %s", ip), http.StatusInternalServerError
		}

		response = fmt.Sprintf("Called remote API succesfuly! msg from api: %s", val)
	}

	return response, nil, 0
}

// ----------- Start mux server --------------

func handleRequests() {
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

// ----------- Main --------------

func main() {
	var err error
	// default rate limit : 5 requests per second
	flag.IntVar(&rateLimit, "rate_limit", 5, "Rate limit for processing requests")
	flag.StringVar(&remoteUrl, "url", "", "Url of remote API")
	flag.Parse()

	if remoteUrl == "" {
		fmt.Println("Error: url is a mandatory argument and must be provided.")
		flag.Usage()
		os.Exit(1)
	}

	// remoteUrl = "https://2oz38.wiremockapi.cloud" // TODO: get from command line arguements?
	remoteDomain, err = getDomainFromUrl(remoteUrl)
	if err != nil {
		log.Fatal(err.Error())
	}

	// apiLimiter = rate.NewLimiter(rate.Every(time.Minute/5), 5)
	rateLimiter = NewRateLimiter(rateLimit, time.Minute)

	handleRequests()
}
