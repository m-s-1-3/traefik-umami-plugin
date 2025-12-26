// Package plugindemo a demo plugin.
package traefik_umami_plugin

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Config the plugin configuration.
type Config struct {
	ForwardPath            string   `json:"forwardPath"`
	UmamiHost              string   `json:"umamiHost"`
	WebsiteId              string   `json:"websiteId"`
	AutoTrack              bool     `json:"autoTrack"`
	DoNotTrack             bool     `json:"doNotTrack"`
	Cache                  bool     `json:"cache"`
	Domains                []string `json:"domains"`
	EvadeGoogleTagManager  bool     `json:"evadeGoogleTagManager"`
	ScriptInjection        bool     `json:"scriptInjection"`
	ScriptInjectionMode    string   `json:"scriptInjectionMode"`
	ServerSideTracking     bool     `json:"serverSideTracking"`
	ServerSideTrackingMode string   `json:"serverSideTrackingMode"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		ForwardPath:            "_umami",
		UmamiHost:              "",
		WebsiteId:              "",
		AutoTrack:              true,
		DoNotTrack:             false,
		Cache:                  false,
		Domains:                []string{},
		EvadeGoogleTagManager:  false,
		ScriptInjection:        true,
		ScriptInjectionMode:    SIModeTag,
		ServerSideTracking:     false,
		ServerSideTrackingMode: SSTModeAll,
	}
}

const (
	SIModeTag          string = "tag"
	SIModeSource       string = "source"
	SSTModeAll         string = "all"
	SSTModeNotinjected string = "notinjected"
)

// PluginHandler a PluginHandler plugin.
type PluginHandler struct {
	next          http.Handler
	name          string
	config        Config
	configIsValid bool
	scriptHtml    string
	LogHandler    *log.Logger
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// construct
	h := &PluginHandler{
		next:          next,
		name:          name,
		config:        *config,
		configIsValid: true,
		scriptHtml:    "",
		LogHandler:    log.New(os.Stdout, "", 0),
	}

	// check if the umami host is set
	if config.UmamiHost == "" {
		h.log("umamiHost is not set!")
		h.configIsValid = false
	}
	// check if the website id is set
	if config.WebsiteId == "" {
		h.log("websiteId is not set!")
		h.configIsValid = false
	}
	// check if scriptInjectionMode is valid
	if config.ScriptInjectionMode != SIModeTag && config.ScriptInjectionMode != SIModeSource {
		h.log("scriptInjectionMode is not valid!")
		h.config.ScriptInjection = false
		h.configIsValid = false
	}
	// check if serverSideTrackingMode is valid
	if config.ServerSideTrackingMode != SSTModeAll && config.ServerSideTrackingMode != SSTModeNotinjected {
		h.log("serverSideTrackingMode is not valid!")
		h.config.ServerSideTracking = false
		h.configIsValid = false
	}

	// build script html
	scriptHtml, err := buildUmamiScript(&h.config)
	h.scriptHtml = scriptHtml
	if err != nil {
		return nil, err
	}

	/*configJSON, _ := json.Marshal(config)
	h.log(fmt.Sprintf("config: %s", configJSON))
	if config.ScriptInjection {
		h.log(fmt.Sprintf("script: %s", scriptHtml))
	} else {
		h.log("script: scriptInjection is false")
	}*/

	return h, nil
}

func (h *PluginHandler) log(message string) {
	level := "info" // default to info
	currentTime := time.Now().Format("2006-01-02T15:04:05Z")

	if h.LogHandler != nil {
		h.LogHandler.Println(fmt.Sprintf("time=\"%s\" level=%s msg=\"[traefik-umami-plugin] %s\"", currentTime, level, message))
	}
}

func (h *PluginHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// check if config is valid
	if !h.configIsValid {
		h.log("Invalid configuration, passing through request")
		h.next.ServeHTTP(rw, req)
		return
	}

	// Forwarding logic: if request URL matches forwarding path, forward regardless of method
	if ok, pathAfter := isUmamiForwardPath(req, &h.config); ok {
		//h.log(fmt.Sprintf("Forward %s", req.URL.EscapedPath()))
		h.forwardToUmami(rw, req, pathAfter)
		return
	}

	// For non-GET requests, pass through unmodified
	if req.Method != http.MethodGet {
		//h.log(fmt.Sprintf("Non-GET request (%s), passing through", req.Method))
		h.next.ServeHTTP(rw, req)
		return
	}

	// For GET requests, process script injection if enabled
	var injected bool = false
	if h.config.ScriptInjection {
		rb := newResponseBuffer(rw)
		h.next.ServeHTTP(rb, req)
		contentType := rb.Header().Get("Content-Type")
		// Only inject script for 2xx responses with text/html content type
		// Skip injection for redirects (3xx) and error responses (4xx, 5xx)
		// Note: statusCode 0 means WriteHeader wasn't called, treat as 200 OK
		statusCode := rb.statusCode
		if statusCode == 0 {
			statusCode = http.StatusOK
		}
		isSuccessResponse := statusCode >= 200 && statusCode < 300
		if isSuccessResponse && strings.HasPrefix(contentType, "text/html") {
			origBytes := rb.buf.Bytes()
			newBytes := regexReplaceSingle(origBytes, insertBeforeRegex, h.scriptHtml)
			if !bytes.Equal(origBytes, newBytes) {
				rb.buf.Reset()
				rb.buf.Write(newBytes)
				injected = true
				//h.log(fmt.Sprintf("Injected script into %s", req.URL.EscapedPath()))
			}
		}
		rb.Flush()
	} else {
		h.next.ServeHTTP(rw, req)
	}

	// Server side tracking for GET requests
	if shouldServerSideTrack(req, &h.config, injected, h) {
		go buildAndSendTrackingRequest(req, &h.config)
	}
}

// responseBuffer buffers the response for script injection.
type responseBuffer struct {
	rw          http.ResponseWriter
	buf         *bytes.Buffer
	statusCode  int
	wroteHeader bool
}

func newResponseBuffer(rw http.ResponseWriter) *responseBuffer {
	return &responseBuffer{
		rw:  rw,
		buf: &bytes.Buffer{},
	}
}

func (rb *responseBuffer) Header() http.Header {
	return rb.rw.Header()
}

func (rb *responseBuffer) WriteHeader(statusCode int) {
	if !rb.wroteHeader {
		rb.statusCode = statusCode
		rb.wroteHeader = true
	}
}

func (rb *responseBuffer) Write(p []byte) (int, error) {
	return rb.buf.Write(p)
}

func (rb *responseBuffer) Flush() {
	if !rb.wroteHeader {
		rb.statusCode = http.StatusOK
	}
	// Update Content-Length header to match actual body size after potential modification
	rb.rw.Header().Set("Content-Length", fmt.Sprintf("%d", rb.buf.Len()))
	rb.rw.WriteHeader(rb.statusCode)
	rb.rw.Write(rb.buf.Bytes())
}
