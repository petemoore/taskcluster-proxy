package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/taskcluster/taskcluster-client-go/tcclient"
	tc "github.com/taskcluster/taskcluster-proxy/taskcluster"
)

type Routes struct {
	// Client ID used to authenticate all proxy requests.
	ClientId string

	// Access Token used to authenticate all proxy requests.
	AccessToken string

	// Certificate used to authenticate proxy requests.
	Certificate string

	// Scopes to use in the delegating authentication.
	Scopes []string
}

var tcServices = tc.NewServices()
var httpClient = &http.Client{}

func (self Routes) signUrl(res http.ResponseWriter, req *http.Request) {
	// create temp credentials with scopes limited to task
	// only works if proxy has permanent scopes
	if self.Certificate != "" {
		res.WriteHeader(403)
		fmt.Printf(res, "This worker type runs its taskcluster proxy server with temporary credentials, and therefore forbids bewit requests, since it cannot sign a request valid only for the task's scopes - consider using a different worker type which has permanent credentials for the taskcluster proxy. Such a proxy can generate temporary credentials with restricted scopes and use this for hawk bewit signing.")
		return
	}
	creds := &tcclient.Credentials{
		ClientId:    self.ClientId,
		AccessToken: self.AccessToken,
	}
	tempCreds, err := creds.CreateTemporaryCredentials(time.Hour*1, self.Scopes...)

	if err != nil {
		res.WriteHeader(500)
		fmt.Printf(res, "Could not create temp credentials - no way to proceed")
		return
	}

	// Using ReadAll could be sketchy here since we are reading unbounded data
	// into memory...
	body, err := ioutil.ReadAll(req.Body)

	if err != nil {
		res.WriteHeader(500)
		fmt.Fprintf(res, "Error reading body")
		return
	}

	urlString := strings.TrimSpace(string(body))
	bewitUrl, err := tc.Bewit(tempCreds.ClientId, tempCreds.AccessToken, tempCreds.Certificate, urlString)

	if err != nil {
		res.WriteHeader(500)
		fmt.Fprintf(res, "Error creating bewit url")
		return
	}

	headers := res.Header()
	headers.Set("Location", bewitUrl)
	res.WriteHeader(303)
	fmt.Fprintf(res, bewitUrl)
}

// Routes implements the `http.Handler` interface
func (self Routes) ServeHTTP(res http.ResponseWriter, req *http.Request) {

	// A special case for the proxy is returning a bewit signed url.
	if req.URL.Path[0:6] == "/bewit" {
		self.signUrl(res, req)
		return
	}

	targetPath, err := tcServices.ConvertPath(req.URL)

	// Unkown service which we are trying to hit...
	if err != nil {
		res.WriteHeader(404)
		log.Printf("Attempting to use unkown service %s", req.URL.String())
		fmt.Fprintf(res, "Unkown taskcluster service: %s", err)
		return
	}

	// Copy method and body over to the proxy request.
	log.Printf("Proxying %s | %s | %s", req.URL, req.Method, targetPath)
	proxyReq, err := http.NewRequest(req.Method, targetPath.String(), req.Body)
	// If we fail to create a request notify the client.
	if err != nil {
		res.WriteHeader(500)
		fmt.Fprintf(res, "Failed to generate proxy request: %s", err)
		return
	}

	// Copy all headers over to the proxy request.
	for key, _ := range req.Header {
		// Do not forward connection!
		if key == "Connection" || key == "Host" {
			continue
		}

		proxyReq.Header.Set(key, req.Header.Get(key))
	}

	// Sign the proxy request with our credentials.
	auth, err := tc.AuthorizationDelegate(
		self.ClientId, self.AccessToken, self.Certificate, self.Scopes, proxyReq,
	)
	if err != nil {
		res.WriteHeader(500)
		fmt.Fprintf(res, "Failed to sign proxy request")
		return
	}
	proxyReq.Header.Set("Authorization", auth)

	// Issue the proxy request...
	proxyResp, err := httpClient.Do(proxyReq)

	if err != nil {
		res.WriteHeader(500)
		fmt.Fprintf(res, "Failed during proxy request: %s", err)
		return
	}

	// Map the headers from the proxy back into our proxyResponse
	headersToSend := res.Header()
	for key, _ := range proxyResp.Header {
		headersToSend.Set(key, proxyResp.Header.Get(key))
	}

	headersToSend.Set("X-Taskcluster-Endpoint", targetPath.String())
	headersToSend.Set("X-Taskcluster-Proxy-Version", version)

	// Write the proxyResponse headers and status.
	res.WriteHeader(proxyResp.StatusCode)

	// Proxy the proxyResponse body from the endpoint to our response.
	io.Copy(res, proxyResp.Body)
	proxyResp.Body.Close()
}
