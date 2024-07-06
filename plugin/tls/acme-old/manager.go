package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	//"github.com/go-acme/lego/v4/registration"
)

var (
	log = clog.NewWithPlugin("tls")
)

type CertAndStore struct {
	Certificate
	Store string
}

type Certificate struct {
	Domain      string `json:"domain,omitempty" toml:"domain,omitempty" yaml:"domain,omitempty"`
	Certificate []byte `json:"certificate,omitempty" toml:"certificate,omitempty" yaml:"certificate,omitempty"`
	Key         []byte `json:"key,omitempty" toml:"key,omitempty" yaml:"key,omitempty"`
}

type Store interface {
	SaveCert(domain string, certData, keyData []byte) error
	GetCert(domain string) (*CertAndStore, error)
}

type Manager struct {
	*Configuration
	ResolverName    string
	Store           Store `json:"store,omitempty" toml:"store,omitempty" yaml:"store,omitempty"`
	certificate     *CertAndStore
	certificatesMu  sync.RWMutex
	account         *Account
	client          *lego.Client
	clientMutex     sync.Mutex
	DnsServerConfig *dnsserver.Config
}

type Configuration struct {
	Email                string        `description:"Email address used for registration." json:"email,omitempty" toml:"email,omitempty" yaml:"email,omitempty"`
	CAServer             string        `description:"CA server to use." json:"caServer,omitempty" toml:"caServer,omitempty" yaml:"caServer,omitempty"`
	PreferredChain       string        `description:"Preferred chain to use." json:"preferredChain,omitempty" toml:"preferredChain,omitempty" yaml:"preferredChain,omitempty" export:"true"`
	Storage              string        `description:"Storage to use." json:"storage,omitempty" toml:"storage,omitempty" yaml:"storage,omitempty" export:"true"`
	KeyType              string        `description:"KeyType used for generating certificate private key. Allow value 'EC256', 'EC384', 'RSA2048', 'RSA4096', 'RSA8192'." json:"keyType,omitempty" toml:"keyType,omitempty" yaml:"keyType,omitempty" export:"true"`
	CertificatesDuration time.Duration `description:"Certificates' duration in hours." json:"certificatesDuration,omitempty" toml:"certificatesDuration,omitempty" yaml:"certificatesDuration,omitempty" export:"true"`
	DNSChallenge         *DNSChallenge `description:"Activate DNS-01 Challenge." json:"dnsChallenge,omitempty" toml:"dnsChallenge,omitempty" yaml:"dnsChallenge,omitempty" label:"allowEmpty" file:"allowEmpty" export:"true"`
}

type DNSChallenge struct {
	Provider                string   `description:"Use a DNS-01 based challenge provider rather than HTTPS." json:"provider,omitempty" toml:"provider,omitempty" yaml:"provider,omitempty" export:"true"`
	DelayBeforeCheck        int      `description:"Assume DNS propagates after a delay in seconds rather than finding and querying nameservers." json:"delayBeforeCheck,omitempty" toml:"delayBeforeCheck,omitempty" yaml:"delayBeforeCheck,omitempty" export:"true"`
	Resolvers               []string `description:"Use following DNS servers to resolve the FQDN authority." json:"resolvers,omitempty" toml:"resolvers,omitempty" yaml:"resolvers,omitempty"`
	DisablePropagationCheck bool     `description:"Disable the DNS propagation checks before notifying ACME that the DNS challenge is ready. [not recommended]" json:"disablePropagationCheck,omitempty" toml:"disablePropagationCheck,omitempty" yaml:"disablePropagationCheck,omitempty" export:"true"`
}

func (m *Manager) Init() error {
	// Initialize Lego client
	//privateKey := generatePrivateKey("RSA4096")
	//privateKeyPEM := encodePrivateKeyToPEM(privateKey)

	account, err := m.initAccount()
	if err != nil {
		return err
	}
	config := lego.NewConfig(account)
	config.CADirURL = m.CAServer
	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create Lego client: %v", err)
	}

	// Register account with ACME server
	//reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	//if err != nil {
	//return fmt.Errorf("failed to register account: %v", err)
	//}

	m.client = client

	// Load existing certificate if available
	cert, err := m.Store.GetCert(m.ResolverName)
	if err == nil {
		m.certificate = cert
		m.updateCoreDNSTLSConfig(cert)
	}

	return nil
}

func (m *Manager) ObtainCertificate(domain string) error {
	m.clientMutex.Lock()
	defer m.clientMutex.Unlock()

	// Obtain certificate using Lego
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}
	certificates, err := m.client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate: %v", err)
	}

	// Save certificate to storage
	err = m.Store.SaveCert(domain, certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	// Update in-memory certificate
	m.certificatesMu.Lock()
	m.certificate = &CertAndStore{
		Certificate: Certificate{
			Domain:      domain,
			Certificate: certificates.Certificate,
			Key:         certificates.PrivateKey,
		},
		Store: m.Configuration.Storage,
	}
	m.certificatesMu.Unlock()

	// Update CoreDNS TLS configuration
	m.updateCoreDNSTLSConfig(m.certificate)

	return nil
}

func (m *Manager) updateCoreDNSTLSConfig(cert *CertAndStore) {
	m.certificatesMu.RLock()
	defer m.certificatesMu.RUnlock()

	// Create TLS certificate
	tlsCert, err := tls.X509KeyPair(cert.Certificate.Certificate, cert.Certificate.Key)
	if err != nil {
		log.Fatalf("failed to create TLS certificate: %v", err)
	}

	// Update DNS server TLS configuration
	m.DnsServerConfig.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
}

func generatePrivateKey(keyType string) crypto.PrivateKey {
	switch keyType {
	case "EC256":
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("Failed to generate EC256 private key: %v", err)
		}
		return privateKey
	case "EC384":
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			log.Fatalf("Failed to generate EC384 private key: %v", err)
		}
		return privateKey
	case "RSA2048":
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Failed to generate RSA2048 private key: %v", err)
		}
		return privateKey
	case "RSA4096":
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			log.Fatalf("Failed to generate RSA4096 private key: %v", err)
		}
		return privateKey
	case "RSA8192":
		privateKey, err := rsa.GenerateKey(rand.Reader, 8192)
		if err != nil {
			log.Fatalf("Failed to generate RSA8192 private key: %v", err)
		}
		return privateKey
	default:
		log.Fatalf("Unsupported key type: %s", keyType)
	}
	return nil
}

func encodePrivateKeyToPEM(key crypto.PrivateKey) []byte {
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			log.Fatalf("Failed to marshal EC private key: %v", err)
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		})
	case *rsa.PrivateKey:
		keyBytes := x509.MarshalPKCS1PrivateKey(key)
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBytes,
		})
	default:
		log.Fatalf("Unsupported private key type")
	}
	return nil
}
