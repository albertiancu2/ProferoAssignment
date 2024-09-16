# Profero Home Assignment

## running

```
go run main.go --rate_limit <num request per minute> --url <remote api url>
```

the flags are not mandatory. rate_limit default value is 5, and I also set a default url

## calls and responses 
The following RESTful service runs on localhost on port 5000 and listens to endpoint /api/v1/test.
I can receive GET request with json body with the structure:

```
​{
  "ip": "192.168.0.1"
}
```

if it receives an intcorrect structure it will return Error Response with structure:
```
{
    "code": 400,
    "message": "<Error Message>"
}
```

If json structure is correct, we check if the ip provided matches the ip of the remote API server we use.

if we find a match we will call the remote API, and if succeded we return success response with structure:

```
{
    "ip_matched": true,
    "message": "<message>"
}
```

In case of failing to connect to the remote API or didn't get the field excpected from if : we will return an Error response.

* if the ips don't match: we will not call the remote api and return success response:

```
{
    "ip_matched": false,
    "message": "Remote api doesn't have ip xxxx"
}
```


## rate limit
I limit number of request we send to the remote api per minute using Sliding Window Algorithm:
I save a list of the current requests to the remote api. Each time a new requests to the remote api is attempted: I remove all the "old request" (that passed 1 minute). If the number of requests left if under the rate_limit I will allow the api call and insert the current request to the array; if the array is rate_limit long the request is blocked and I send Error Response:

```
{
    "code": 429,
    "message": "Rate limit of N requests per minute exceeded!"
}
```





