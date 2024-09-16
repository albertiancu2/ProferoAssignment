package main

import (
	"container/list"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var rateLimit int
var rateLimiter *RateLimiter
var remoteUrl string
var remoteDomain string

type testRequest struct {
	IP string `json:"ip"`
}

type testSuccessResponse struct {
	IpMatched bool   `json:"ip_matched"`
	Message   string `json:"message"`
}

type testErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ----------- Rate Limiter --------------
// Sliding Window Algorithm
type RateLimiter struct {
	RateLimit int
	Interval  time.Duration
	Requests  *list.List
	Mutex     sync.Mutex
}

func NewRateLimiter(maxRequests int, interval time.Duration) *RateLimiter {
	return &RateLimiter{
		RateLimit: maxRequests,
		Interval:  interval,
		Requests:  list.New(),
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.Mutex.Lock()
	defer rl.Mutex.Unlock()

	now := time.Now()
	startOfInterval := now.Add(-rl.Interval)

	// remove all the requests that passed Interval (were received more than 1 minute before)
	for e := rl.Requests.Front(); e != nil; {
		next := e.Next()
		if e.Value.(time.Time).Before(startOfInterval) {
			rl.Requests.Remove(e)
		} else {
			break
		}
		e = next
	}
	// allow the request only if less than rate_limit request where performed in the last endpoint
	if rl.Requests.Len() < rl.RateLimit {
		rl.Requests.PushBack(now)
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

func SendHttpResponse(w http.ResponseWriter, status int, response interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response)
}

func SendErrorResponse(w http.ResponseWriter, errorCode int, message string) {
	responseObj := testErrorResponse{
		Code:    errorCode,
		Message: strings.ReplaceAll(message, "\"", "'"),
	}
	SendHttpResponse(w, errorCode, responseObj)
}

// ----------- Handler Functions --------------

func checkIpAddress(w http.ResponseWriter, r *http.Request) {
	var requestBody testRequest
	var err error

	err = decodeJson(r, &requestBody)
	if err != nil {
		SendErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	if requestBody.IP == "" {
		SendErrorResponse(w, http.StatusBadRequest, "ip field is missing or empty")
		return
	}

	ipMatched, err := checkIpMatch(requestBody.IP)
	if err != nil {
		SendErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	var responseTxt string
	if ipMatched {
		valFromApi, err, httpErrorCode := getCheckIpAddressResponse(requestBody.IP)
		if err != nil {
			SendErrorResponse(w, httpErrorCode, err.Error())
			return
		}
		responseTxt = fmt.Sprintf("Called remote API succesfuly! msg from api: %s", valFromApi)
	} else {
		responseTxt = fmt.Sprintf("Remote api doesn't have ip %s", requestBody.IP)
	}

	resonseObj := testSuccessResponse{
		IpMatched: ipMatched,
		Message:   responseTxt,
	}

	SendHttpResponse(w, http.StatusOK, resonseObj)
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

// The the domain from the url provided
func getDomainFromUrl(providedUrl string) (string, error) {
	urlParsed, err := url.Parse(providedUrl)
	if err != nil {
		return "", fmt.Errorf("error parsing url provided")
	}

	return urlParsed.Host, nil
}

// The the IP address from the domain
func nslookup(domain string) ([]string, error) {
	ips, err := net.LookupHost(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup domain '%s': %w", domain, err)
	}
	return ips, nil
}

// Check if the provided ip in the json is corresponding to the remote api ip
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

// Call remote API and return the response
func getCheckIpAddressResponse(ip string) (string, error, int) {
	if !rateLimiter.Allow() {
		return "", fmt.Errorf("Rate limit of %d requests per minute exceeded!", rateLimit), http.StatusTooManyRequests
	}

	remoteApiResponse, err := SendGetRequest(remoteUrl + "/json")
	if err != nil {
		return "", fmt.Errorf("error retreiving data form ip %s. %s", ip, err.Error()), http.StatusInternalServerError
	}

	val, ok := remoteApiResponse["value"].(string)
	if !ok {
		return "", fmt.Errorf("Error with value received from ip %s", ip), http.StatusInternalServerError
	}

	return val, nil, 0
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
	flag.StringVar(&remoteUrl, "url", "https://2oz38.wiremockapi.cloud", "Url of remote API")
	flag.Parse()

	remoteDomain, err = getDomainFromUrl(remoteUrl)
	if err != nil {
		log.Fatal(err.Error())
	}

	rateLimiter = NewRateLimiter(rateLimit, time.Minute)

	handleRequests()
}
