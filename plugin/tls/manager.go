package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
)

// CertManager takes care of obtaining and renewing TLS certificates
type CertManager struct {
	Config *lego.Config
	Zone   string
}

func newCertManager(zone string, config *lego.Config) *CertManager {
	return &CertManager{
		Config: config,
		Zone:   zone,
	}
}

func setupCertPool(caCert string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	if caCert != "" {
		certbytes, err := os.ReadFile(caCert)
		if err != nil {
			return nil, err
		}
		pemcert, _ := pem.Decode(certbytes)
		if pemcert == nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(pemcert.Bytes)
		if err != nil {
			return nil, err
		}
		pool.AddCert(cert)
	}
	return pool, nil
}

func (c *CertManager) configureTLSwithACME(ctx context.Context) (*tls.Config, error) {
	var err error

	// try loading existing certificate
	cert, err = c.cacheCertificate(ctx, c.Zone)
	if err != nil {
		log.Info("Obtaining TLS Certificate, may take a moment")
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, err
		}
		err = c.obtainCert(c.Zone)
		if err != nil {
			return nil, nil, err
		}
		cert, err = c.cacheCertificate(ctx, c.Zone)
		if err != nil {
			return nil, nil, err
		}
	}

	// check if renewal is required
	if cert.NeedsRenewal(c.Config) {
		log.Info("Renewing TLS Certificate")
		var err error
		err = c.renewCert(ctx, c.Zone)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: renewing certificate: %w", c.Zone, err)
		}
		// successful renewal, so update in-memory cache
		cert, err = c.cacheCertificate(ctx, c.Zone)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: reloading renewed certificate into memory: %v", c.Zone, err)
		}
	}

	// check again, if it still needs renewal something went wrong
	if cert.NeedsRenewal(c.Config) {
		log.Error("Failed to renew certificate")
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert.Certificate}}
	tlsConfig.ClientAuth = tls.NoClientCert
	tlsConfig.ClientCAs = tlsConfig.RootCAs

	return tlsConfig, &cert, nil
}
