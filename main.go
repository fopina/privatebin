package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/fopina/privatebin/types"
	"github.com/fopina/privatebin/utils"
	"golang.org/x/crypto/pbkdf2"
)

const (
	specIterations      = 100000
	specKeySize         = 256
	specTagSize         = 128
	specAlgorithm       = "aes"
	specMode            = "gcm"
	specCompression     = "none"
	pbDefaultURL        = "privatebin.net"
	pbDefaultExpiration = "1week"
)

// PasteRequest .
type PasteRequest struct {
	V     int              `json:"v"`
	AData []interface{}    `json:"adata"`
	Meta  PasteRequestMeta `json:"meta"`
	CT    string           `json:"ct"`
}

// PasteRequestMeta .
type PasteRequestMeta struct {
	Expire string `json:"expire"`
}

// PasteResponse .
type PasteResponse struct {
	Status      int    `json:"status"`
	ID          string `json:"id"`
	URL         string `json:"url"`
	DeleteToken string `json:"deletetoken"`
	Message     string `json:"message"`
}

// PasteContent .
type PasteContent struct {
	Paste          string `json:"paste"`
	Attachment     string `json:"attachment,omitempty"`
	AttachmentName string `json:"attachment_name,omitempty"`
}

// PasteSpec .
type PasteSpec struct {
	IV          string
	Salt        string
	Iterations  int
	KeySize     int
	TagSize     int
	Algorithm   string
	Mode        string
	Compression string
}

// SpecArray .
func (spec *PasteSpec) SpecArray() []interface{} {
	return []interface{}{
		spec.IV,
		spec.Salt,
		spec.Iterations,
		spec.KeySize,
		spec.TagSize,
		spec.Algorithm,
		spec.Mode,
		spec.Compression,
	}
}

// PasteData .
type PasteData struct {
	*PasteSpec
	Data []byte
}

// adata .
func (paste *PasteData) adata() []interface{} {
	return []interface{}{
		paste.SpecArray(),
		"plaintext",
		0,
		0,
	}
}

var version string = "DEV"
var date string

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "pbin:", err)
		os.Exit(1)
	}
}

func run() error {
	versionPtr := flag.BoolP("version", "v", false, "display version")
	urlPtr := flag.StringP("url", "u", pbDefaultURL, "privatebin host")
	attachmentPtr := flag.StringP("attach", "a", "", "attach a file")
	expiration := types.ExpirationValue("1week")
	flag.VarP(&expiration, "expire", "e", "expiration")
	flag.Parse()

	if *versionPtr {
		fmt.Println("Version: " + version + " (built on " + date + ")")
		return nil
	}

	pbURL := strings.TrimRight(*urlPtr, "/")
	if !strings.Contains(pbURL, "://") {
		pbURL = "https://" + pbURL
	}

	// Read from STDIN (Piped input)
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}

	// Remove extra line breaks to prevent PrivateBin from breaking.
	if bytes.HasSuffix(input, []byte("\n")) {
		input = input[:len(input)-1]
	}

	pc := PasteContent{Paste: utils.StripANSI(string(input))}
	if *attachmentPtr != "" {
		data, err := os.ReadFile(*attachmentPtr)
		if err != nil {
			return fmt.Errorf("read attachment: %w", err)
		}
		pc.Attachment = utils.Base64(data)
		pc.AttachmentName = filepath.Base(*attachmentPtr)
	}
	// Marshal the paste content to escape JSON characters.
	pasteContent, err := json.Marshal(&pc)
	if err != nil {
		return fmt.Errorf("encode paste: %w", err)
	}

	// Generate a master key for the paste.
	masterKey, err := utils.GenRandomBytes(32)
	if err != nil {
		return fmt.Errorf("generate encryption key: %w", err)
	}

	// Encrypt the paste data
	pasteData, err := encrypt(masterKey, pasteContent)
	if err != nil {
		return fmt.Errorf("encrypt paste: %w", err)
	}

	// Create a new Paste Request.
	pasteRequest := &PasteRequest{
		V:     2,
		AData: pasteData.adata(),
		Meta: PasteRequestMeta{
			Expire: expiration.String(),
		},
		CT: utils.Base64(pasteData.Data),
	}

	// Get the Request Body.
	body, err := json.Marshal(pasteRequest)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}

	// Create a new HTTP Client and HTTP Request.
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("POST", pbURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// Set the request headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	req.Header.Set("X-Requested-With", "JSONHttpRequest")

	// Run the http request.
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send paste to %s: %w", pbURL, err)
	}
	defer res.Body.Close()

	// Read the response body.
	response, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read server response: %w", err)
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("server returned HTTP %s: %s", res.Status, strings.TrimSpace(string(response)))
	}

	// Decode the response.
	pasteResponse := &PasteResponse{}
	if err := json.Unmarshal(response, &pasteResponse); err != nil {
		return fmt.Errorf("decode server response: %w", err)
	}
	if pasteResponse.Status != 0 {
		if pasteResponse.Message == "" {
			return fmt.Errorf("server rejected paste (status %d)", pasteResponse.Status)
		}
		return fmt.Errorf("server rejected paste: %s", pasteResponse.Message)
	}
	if pasteResponse.URL == "" {
		return fmt.Errorf("server response did not include a paste URL")
	}

	fmt.Printf("%s%s#%s\n", pbURL, pasteResponse.URL, base58.Encode(masterKey))
	return nil
}

func encrypt(master []byte, message []byte) (*PasteData, error) {
	// Generate a initialization vector.
	iv, err := utils.GenRandomBytes(12)
	if err != nil {
		return nil, err
	}

	// Generate salt.
	salt, err := utils.GenRandomBytes(8)
	if err != nil {
		return nil, err
	}

	// Create the Paste Data and generate a key.
	paste := &PasteData{
		PasteSpec: &PasteSpec{
			IV:          utils.Base64(iv),
			Salt:        utils.Base64(salt),
			Iterations:  specIterations,
			KeySize:     specKeySize,
			TagSize:     specTagSize,
			Algorithm:   specAlgorithm,
			Mode:        specMode,
			Compression: specCompression,
		},
	}
	key := pbkdf2.Key(master, salt, paste.Iterations, 32, sha256.New)

	// Get the "adata" for the paste.
	adata, err := json.Marshal(paste.adata())
	if err != nil {
		return nil, err
	}

	// Create a new Cipher
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM.
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	// Sign the message.
	data := gcm.Seal(nil, iv, message, adata)

	// Update and return the paste data.
	paste.Data = data

	return paste, nil
}
