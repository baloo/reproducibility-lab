package main

import (
	"compress/gzip"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

type handler struct {
}

func (h *handler) buildImage(derivation string) string {
	image, _ := exec.Command("nix-store", "--realize", derivation).Output()

	return strings.TrimSpace(string(image))
}

func (h *handler) buildDerivation() string {
	derivation, _ := exec.Command("nix-instantiate", "../http-image.nix").Output()

	return strings.TrimSpace(string(derivation))
}

// EDK2 UEFI does not negociate gzip :(
// This function is useless for now
// 
// Feeds gzip garbage data (deflate to empty bytestring), until an image is built
func (h *handler) ServeHTTPGzip(w http.ResponseWriter, r *http.Request) {
        // There are 2 http spec violation here:
        //  - The content-encoding should be negociated by the client
        //  - Transfer-Encoding chunked is only available on http/1.1 
	f := w.(http.Flusher)

	w.Header().Add("Transfer-Encoding", "chunked")
	// We want the content in gzip, middleman proxies should not alter it
	w.Header().Add("Cache-Control", "no-transform")
	w.Header().Add("Content-Encoding", "gzip")
	w.WriteHeader(http.StatusOK)

	gzipWriter := gzip.NewWriter(w)

	stopSignal := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopSignal:
				close(stopSignal)
				return
			default:
				gzipWriter.Write([]byte{})
				gzipWriter.Flush()
				f.Flush()
			}
			time.Sleep(5 * time.Second)
		}
	}()

	derivation := h.buildDerivation()
	log.Printf("derivation: %s", derivation)
	image := h.buildImage(derivation)
	log.Printf("output image: %s", image)

	imageReader, err := os.OpenFile(image+"/linux.efi", os.O_RDONLY, 0644)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer imageReader.Close()
	stopSignal <- struct{}{}

	var sendContent io.Reader = imageReader
	io.Copy(gzipWriter, sendContent)

	gzipWriter.Flush()
	f.Flush()
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	derivation := h.buildDerivation()
	log.Printf("derivation: %s", derivation)
	image := h.buildImage(derivation)
	log.Printf("output image: %s", image)

	http.ServeFile(w, r, image+"/linux.efi")
}

func main() {

	http.Handle("/image", &handler{})

	log.Fatal(http.ListenAndServe(":8000", nil))
}
