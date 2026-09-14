/*
Copyright 2026 The kmp-issuer Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package kmp

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// pemPrivateKeyType is the block type of a PKCS#8 private key.
const pemPrivateKeyType = "PRIVATE KEY"

// jksMagic starts every Java key store, which this package cannot open.
var jksMagic = []byte{0xFE, 0xED, 0xFE, 0xED}

// PrivateKey is a key Key Manager Plus generated and holds in escrow.
type PrivateKey struct {
	// Key is the parsed private key.
	Key crypto.PrivateKey
	// PEM is the key re-encoded as an unencrypted PKCS#8 PEM block, which is
	// what a Kubernetes TLS Secret holds.
	PEM []byte
}

// ParseExportedPrivateKey reads the private key out of an exportCSR response.
//
// Key Manager Plus may answer with the key file itself or wrap its content in a
// JSON envelope, and the file may be PEM or bare base64 encoded DER, so each is
// tried in turn. Key stores are not opened: PKCS#12 and JKS need a library this
// controller does not carry, and the export can be asked for the PrivateKey
// file type instead.
func ParseExportedPrivateKey(data []byte, password string) (*PrivateKey, error) {
	if len(data) == 0 {
		return nil, errors.New("the export is empty")
	}

	candidates := []string{string(data)}
	if parsed, err := parseResponse(data); err == nil {
		// A JSON envelope: the key is one of the strings inside it.
		candidates = append(candidates, parsed.collectStrings()...)
	}

	var firstErr error
	for _, candidate := range candidates {
		key, err := parsePrivateKeyCandidate(candidate, password)
		if err != nil {
			if firstErr == nil && err != errNoPrivateKey {
				firstErr = err
			}
			continue
		}
		encoded, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("re-encoding the exported private key: %w", err)
		}
		return &PrivateKey{
			Key: key,
			PEM: pem.EncodeToMemory(&pem.Block{Type: pemPrivateKeyType, Bytes: encoded}),
		}, nil
	}

	if firstErr != nil {
		return nil, firstErr
	}
	if isKeyStore(data) {
		return nil, errors.New("the export is a key store, which this controller cannot open: " +
			"ask Key Manager Plus for the PrivateKey file type instead of KeyStore")
	}
	return nil, errors.New("no private key found in the export")
}

// errNoPrivateKey marks a candidate that simply is not a key, as opposed to a
// key that could not be read.
var errNoPrivateKey = errors.New("not a private key")

func parsePrivateKeyCandidate(candidate, password string) (crypto.PrivateKey, error) {
	if strings.Contains(candidate, "-----BEGIN") {
		return parsePEMPrivateKey([]byte(candidate), password)
	}

	compact := strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t', ' ':
			return -1
		}
		return r
	}, candidate)
	if len(compact) < 64 {
		return nil, errNoPrivateKey
	}
	der, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return nil, errNoPrivateKey
	}
	key, err := parseDERPrivateKey(der)
	if err != nil {
		return nil, errNoPrivateKey
	}
	return key, nil
}

// parsePEMPrivateKey reads the first private key block of a PEM document,
// decrypting it when it carries a legacy encryption header.
func parsePEMPrivateKey(data []byte, password string) (crypto.PrivateKey, error) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errNoPrivateKey
		}
		if !strings.Contains(block.Type, "PRIVATE KEY") {
			continue
		}

		der := block.Bytes
		//nolint:staticcheck // The legacy PEM encryption is weak, but it is what
		// Key Manager Plus emits for a password protected export, and refusing
		// to read it would leave the key unusable.
		if x509.IsEncryptedPEMBlock(block) {
			if password == "" {
				return nil, errors.New("the exported private key is encrypted but no password is configured")
			}
			decrypted, err := x509.DecryptPEMBlock(block, []byte(password)) //nolint:staticcheck // see above
			if err != nil {
				return nil, fmt.Errorf("decrypting the exported private key: %w", err)
			}
			der = decrypted
		} else if block.Type == "ENCRYPTED PRIVATE KEY" {
			return nil, errors.New("the exported private key uses PKCS#8 encryption, which this controller " +
				"cannot decrypt: configure Key Manager Plus to export the key unencrypted")
		}

		key, err := parseDERPrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("parsing the exported private key: %w", err)
		}
		return key, nil
	}
}

// parseDERPrivateKey accepts the three DER encodings Go can read.
func parseDERPrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("the key is not in PKCS#8, PKCS#1 or SEC 1 form")
}

// isKeyStore reports whether the export looks like a key store rather than a
// key, so that the error can say what to change.
func isKeyStore(data []byte) bool {
	if len(data) >= 4 && string(data[:4]) == string(jksMagic) {
		return true
	}
	// A PKCS#12 file is a DER SEQUENCE and, unlike a PEM export, is binary.
	return len(data) > 2 && data[0] == 0x30 && !isMostlyText(data)
}

func isMostlyText(data []byte) bool {
	limit := min(len(data), 512)
	printable := 0
	for _, b := range data[:limit] {
		if b == '\n' || b == '\r' || b == '\t' || (b >= 0x20 && b < 0x7F) {
			printable++
		}
	}
	return printable*10 >= limit*9
}

// MatchesCertificate reports whether the key belongs to the certificate. A
// mismatch means the wrong key was exported, and the pair would be unusable.
func (k *PrivateKey) MatchesCertificate(cert *x509.Certificate) bool {
	signer, ok := k.Key.(interface{ Public() crypto.PublicKey })
	if !ok {
		return false
	}
	matcher, ok := cert.PublicKey.(publicKeyMatcher)
	if !ok {
		return false
	}
	return matcher.Equal(signer.Public())
}
