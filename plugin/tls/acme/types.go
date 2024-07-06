package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/patrickmn/go-cache"
)

// Domain holds a domain name with SANs.
type Domain struct {
	// Main defines the main domain name.
	Main string `description:"Default subject name." json:"main,omitempty" toml:"main,omitempty" yaml:"main,omitempty"`
	// SANs defines the subject alternative domain names.
	SANs []string `description:"Subject alternative names." json:"sans,omitempty" toml:"sans,omitempty" yaml:"sans,omitempty"`
}

// ToStrArray convert a domain into an array of strings.
func (d *Domain) ToStrArray() []string {
	var domains []string
	if len(d.Main) > 0 {
		domains = []string{d.Main}
	}
	return append(domains, d.SANs...)
}

// Set sets a domains from an array of strings.
func (d *Domain) Set(domains []string) {
	if len(domains) > 0 {
		d.Main = domains[0]
		d.SANs = domains[1:]
	}
}

// CertificateStore store for dynamic certificates.
type CertificateStore struct {
	DynamicCerts       *Safe
	DefaultCertificate *tls.Certificate
	CertCache          *cache.Cache
}

// Safe contains a thread-safe value.
type Safe struct {
	value interface{}
	lock  sync.RWMutex
}

// New create a new Safe instance given a value.
func New(value interface{}) *Safe {
	return &Safe{value: value, lock: sync.RWMutex{}}
}

// Get returns the value.
func (s *Safe) Get() interface{} {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.value
}

// Set sets a new value.
func (s *Safe) Set(value interface{}) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.value = value
}

// Configuration is the root of the dynamic configuration.
type TlsConfiguration struct {
	TLS *TLSConfiguration `json:"tls,omitempty" toml:"tls,omitempty" yaml:"tls,omitempty" export:"true"`
}

// +k8s:deepcopy-gen=true

// TLSConfiguration contains all the configuration parameters of a TLS connection.
type TLSConfiguration struct {
	Certificates []*CertAndStores      `json:"certificates,omitempty"  toml:"certificates,omitempty" yaml:"certificates,omitempty" label:"-" export:"true"`
	Options      map[string]TlsOptions `json:"options,omitempty" toml:"options,omitempty" yaml:"options,omitempty" label:"-" export:"true"`
	Stores       map[string]TlsStore   `json:"stores,omitempty" toml:"stores,omitempty" yaml:"stores,omitempty" export:"true"`
}

// Certificate holds a SSL cert/key pair
// Certs and Key could be either a file path, or the file content itself.
type TlsCertificate struct {
	CertFile FileOrContent `json:"certFile,omitempty" toml:"certFile,omitempty" yaml:"certFile,omitempty"`
	KeyFile  FileOrContent `json:"keyFile,omitempty" toml:"keyFile,omitempty" yaml:"keyFile,omitempty" loggable:"false"`
}

// Certificates defines traefik certificates type
// Certs and Keys could be either a file path, or the file content itself.
type Certificates []Certificate

// CertAndStores allows mapping a TLS certificate to a list of entry points.
type CertAndStores struct {
	TlsCertificate `yaml:",inline" export:"true"`
	Stores         []string `json:"stores,omitempty" toml:"stores,omitempty" yaml:"stores,omitempty" export:"true"`
}

const (
	// DefaultTLSConfigName is the name of the default set of options for configuring TLS.
	DefaultTLSConfigName = "default"
	// DefaultTLSStoreName is the name of the default store of TLS certificates.
	// Note that it actually is the only usable one for now.
	DefaultTLSStoreName = "default"
)

// Pool is a pool of go routines.
type Pool struct {
	waitGroup sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
}

// FileOrContent holds a file path or content.
type FileOrContent string

// String returns the FileOrContent in string format.
func (f FileOrContent) String() string {
	return string(f)
}

// IsPath returns true if the FileOrContent is a file path, otherwise returns false.
func (f FileOrContent) IsPath() bool {
	_, err := os.Stat(f.String())
	return err == nil
}

// Read returns the content after reading the FileOrContent variable.
func (f FileOrContent) Read() ([]byte, error) {
	var content []byte
	if f.IsPath() {
		var err error
		content, err = os.ReadFile(f.String())
		if err != nil {
			return nil, err
		}
	} else {
		content = []byte(f)
	}
	return content, nil
}

// MatchDomain returns true if a domain match the cert domain.
func MatchDomain(domain, certDomain string) bool {
	if domain == certDomain {
		return true
	}

	for len(certDomain) > 0 && certDomain[len(certDomain)-1] == '.' {
		certDomain = certDomain[:len(certDomain)-1]
	}

	labels := strings.Split(domain, ".")
	for i := range labels {
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		if certDomain == candidate {
			return true
		}
	}
	return false
}

// CanonicalDomain returns a lower case domain with trim space.
func CanonicalDomain(domain string) string {
	return strings.ToLower(strings.TrimSpace(domain))
}

// Store holds the options for a given Store.
type TlsStore struct {
	DefaultCertificate   *TlsCertificate `json:"defaultCertificate,omitempty" toml:"defaultCertificate,omitempty" yaml:"defaultCertificate,omitempty" label:"-" export:"true"`
	DefaultGeneratedCert *GeneratedCert  `json:"defaultGeneratedCert,omitempty" toml:"defaultGeneratedCert,omitempty" yaml:"defaultGeneratedCert,omitempty" export:"true"`
}

// GeneratedCert defines the default generated certificate configuration.
type GeneratedCert struct {
	// Resolver is the name of the resolver that will be used to issue the DefaultCertificate.
	Resolver string `json:"resolver,omitempty" toml:"resolver,omitempty" yaml:"resolver,omitempty" export:"true"`
	// Domain is the domain definition for the DefaultCertificate.
	Domain *Domain `json:"domain,omitempty" toml:"domain,omitempty" yaml:"domain,omitempty" export:"true"`
}

// Options configures TLS for an entry point.
type TlsOptions struct {
	MinVersion       string     `json:"minVersion,omitempty" toml:"minVersion,omitempty" yaml:"minVersion,omitempty" export:"true"`
	MaxVersion       string     `json:"maxVersion,omitempty" toml:"maxVersion,omitempty" yaml:"maxVersion,omitempty" export:"true"`
	CipherSuites     []string   `json:"cipherSuites,omitempty" toml:"cipherSuites,omitempty" yaml:"cipherSuites,omitempty" export:"true"`
	CurvePreferences []string   `json:"curvePreferences,omitempty" toml:"curvePreferences,omitempty" yaml:"curvePreferences,omitempty" export:"true"`
	ClientAuth       ClientAuth `json:"clientAuth,omitempty" toml:"clientAuth,omitempty" yaml:"clientAuth,omitempty"`
	SniStrict        bool       `json:"sniStrict,omitempty" toml:"sniStrict,omitempty" yaml:"sniStrict,omitempty" export:"true"`
	ALPNProtocols    []string   `json:"alpnProtocols,omitempty" toml:"alpnProtocols,omitempty" yaml:"alpnProtocols,omitempty" export:"true"`

	// Deprecated: https://github.com/golang/go/issues/45430
	PreferServerCipherSuites *bool `json:"preferServerCipherSuites,omitempty" toml:"preferServerCipherSuites,omitempty" yaml:"preferServerCipherSuites,omitempty" export:"true"`
}

// ClientAuth defines the parameters of the client authentication part of the TLS connection, if any.
type ClientAuth struct {
	CAFiles []FileOrContent `json:"caFiles,omitempty" toml:"caFiles,omitempty" yaml:"caFiles,omitempty"`
	// ClientAuthType defines the client authentication type to apply.
	// The available values are: "NoClientCert", "RequestClientCert", "VerifyClientCertIfGiven" and "RequireAndVerifyClientCert".
	ClientAuthType string `json:"clientAuthType,omitempty" toml:"clientAuthType,omitempty" yaml:"clientAuthType,omitempty" export:"true"`
}

// getStore returns the store found for storeName, or nil otherwise.
func (m *AcmeManager) getStore(storeName string) *CertificateStore {
	st, ok := m.stores[storeName]
	if !ok {
		return nil
	}
	return st
}

// GetStore gets the certificate store of a given name.
func (m *AcmeManager) GetStore(storeName string) *CertificateStore {
	m.lock.RLock()
	defer m.lock.RUnlock()

	return m.getStore(storeName)
}

// GetAllDomains return a slice with all the certificate domain.
func (c CertificateStore) GetAllDomains() []string {
	allDomains := c.getDefaultCertificateDomains()

	// Get dynamic certificates
	if c.DynamicCerts != nil && c.DynamicCerts.Get() != nil {
		for domain := range c.DynamicCerts.Get().(map[string]*tls.Certificate) {
			allDomains = append(allDomains, domain)
		}
	}

	return allDomains
}

func (c CertificateStore) getDefaultCertificateDomains() []string {
	var allCerts []string

	if c.DefaultCertificate == nil {
		return allCerts
	}

	x509Cert, err := x509.ParseCertificate(c.DefaultCertificate.Certificate[0])
	if err != nil {
		fmt.Println("Could not parse default certificate")
		return allCerts
	}

	if len(x509Cert.Subject.CommonName) > 0 {
		allCerts = append(allCerts, x509Cert.Subject.CommonName)
	}

	allCerts = append(allCerts, x509Cert.DNSNames...)

	for _, ipSan := range x509Cert.IPAddresses {
		allCerts = append(allCerts, ipSan.String())
	}

	return allCerts
}
