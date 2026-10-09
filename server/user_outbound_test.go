package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/juicity/juicity/pkg/log"
)

func writeTestCert(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDer, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}), 0o600)
	return certPath, keyPath
}

func TestUserOutboundsRouteByUser(t *testing.T) {
	cert, key := writeTestCert(t)
	marked, chained, plain := uuid.New(), uuid.New(), uuid.New()
	s, err := New(&Options{
		Logger:      log.NewLogger(&log.Options{}),
		Users:       map[string]string{marked.String(): "a", chained.String(): "b", plain.String(): "c"},
		Certificate: cert,
		PrivateKey:  key,
		Fwmark:      3,
		UserOutbounds: map[string]UserOutbound{
			marked.String():  {Mark: 7},
			chained.String(): {Mark: 8, Socks5: "10.201.0.1:1080"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d, mark := s.route(&marked); mark != 7 || d == s.dialer {
		t.Errorf("marked user: mark %d, own dialer %v", mark, d != s.dialer)
	}
	if d, mark := s.route(&chained); mark != 8 || d == s.dialer {
		t.Errorf("chained user: mark %d, own dialer %v", mark, d != s.dialer)
	}
	if d, mark := s.route(&plain); mark != 3 || d != s.dialer {
		t.Errorf("plain user should use the server's dialer and fwmark, got mark %d", mark)
	}
	if _, mark := s.route(nil); mark != 3 {
		t.Errorf("unauthenticated: mark %d", mark)
	}
}

func TestUserOutboundsRejectBadEntries(t *testing.T) {
	cert, key := writeTestCert(t)
	_, err := New(&Options{
		Logger: log.NewLogger(&log.Options{}), Certificate: cert, PrivateKey: key,
		UserOutbounds: map[string]UserOutbound{"not-a-uuid": {Mark: 1}},
	})
	if err == nil {
		t.Fatal("expected an error for a bad UUID")
	}
}
