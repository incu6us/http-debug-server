package main

import (
    "crypto/tls"
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "net"
    "net/http"
    "os"
)

var (
    port   string
    caCert string
    caKey  string
    isHelp bool
)

var tlsInfoChan = make(chan output)

func connStateHook(c net.Conn, state http.ConnState) {
    log.Printf("Remote address: %s", c.RemoteAddr())
    if state == http.StateActive {
        if cc, ok := c.(*tls.Conn); ok {
            state := cc.ConnectionState()
            switch state.Version {
            case tls.VersionSSL30:
                log.Println("negotiated to Version: VersionSSL30")
            case tls.VersionTLS10:
                log.Println("negotiated to Version: VersionTLS10")
            case tls.VersionTLS11:
                log.Println("negotiated to Version: VersionTLS11")
            case tls.VersionTLS12:
                log.Println("negotiated to Version: VersionTLS12")
            default:
                log.Println("negotiated to Unknown TLS version")
            }
        }
    }
}

type output struct {
    SupportedSuites []string `json:"supported_suites"`
    SupportedCurves []string `json:"supported_curves"`
    SupportedPoints []string `json:"supported_points"`
}

func getCertificateHook(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
    o := &output{}
    for _, suite := range helloInfo.CipherSuites {
        if v, exists := CipherSuiteMap[suite]; exists {
            o.SupportedSuites = append(o.SupportedSuites, v)
        } else {
            o.SupportedSuites = append(o.SupportedSuites, fmt.Sprintf("Unknown, 0x%x", suite))
        }
    }

    for _, curve := range helloInfo.SupportedCurves {
        if v, exists := CurveMap[curve]; exists {
            o.SupportedCurves = append(o.SupportedCurves, v)
        } else {
            o.SupportedCurves = append(o.SupportedCurves, fmt.Sprintf("Unknown, 0x%x", curve))
        }
        // http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
    }
    for _, point := range helloInfo.SupportedPoints {
        // http://tools.ietf.org/html/rfc4492#section-5.1.2).
        o.SupportedPoints = append(o.SupportedPoints, fmt.Sprintf("0x%x", point))
    }

    j, _ := json.Marshal(o)
    log.Printf("Certificate hook output: %#v", string(j))
    return nil, nil
}

func getClientCertificate(certReqInfo *tls.CertificateRequestInfo) (*tls.Certificate, error) {
    log.Printf("Client cert info: %#v", certReqInfo)
    return nil, nil
}

var debugHandler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/plain")
    log.Printf("URL: %#v", r.URL)
    log.Printf("Request: %#v", r)
    log.Printf("TLS: %#v", r.TLS)
    log.Printf("TLS-Unique: %#v", r.TLS.TLSUnique)
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(fmt.Sprintf("Headers: %#v", r)))
    log.Printf("Server name: %s", r.TLS.ServerName)
}

func main() {
    flag.StringVar(&port, "p", "", "Listen on")
    flag.StringVar(&caCert, "cert", "", "ca.crt")
    flag.StringVar(&caKey, "key", "", "private.key")
    flag.BoolVar(&isHelp, "h", false, "Help\n use the endpoint to see a debug: http://{host}:{port}/")
    flag.Parse()

    if port == "" || isHelp {
        flag.PrintDefaults()
        os.Exit(1)
    }

    s := &http.Server{
        Addr:      ":" + port,
        ConnState: connStateHook,
        Handler:   debugHandler,
        TLSConfig: &tls.Config{
            GetCertificate: getCertificateHook,
            GetClientCertificate: getClientCertificate,
            ClientAuth: tls.RequestClientCert,
        },
    }

    if caCert == "" {
        log.Printf("Starting on: %s", port)
        log.Fatal(s.ListenAndServe())
    } else {
        log.Printf("Starting TLS connection on: %s", port)
        log.Fatal(s.ListenAndServeTLS(caCert, caKey))
    }
}
