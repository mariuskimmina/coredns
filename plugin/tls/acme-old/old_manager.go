package acme

//
//import (
//	"context"
//	"crypto/tls"
//	"crypto/x509"
//	"errors"
//	"fmt"
//	"net/url"
//
//	//"sort"
//	"strings"
//	"sync"
//	"time"
//
//	"github.com/coredns/coredns/core/dnsserver"
//	"github.com/coredns/coredns/coremain"
//	clog "github.com/coredns/coredns/plugin/pkg/log"
//	"github.com/go-acme/lego/v4/certificate"
//	"github.com/go-acme/lego/v4/challenge"
//	"github.com/go-acme/lego/v4/challenge/dns01"
//	"github.com/go-acme/lego/v4/lego"
//	"github.com/go-acme/lego/v4/providers/dns"
//	"github.com/go-acme/lego/v4/registration"
//)
//
//var (
//	log = clog.NewWithPlugin("tls")
//)
//
//const resolverSuffix = ".acme"
//
//const (
//	// DefaultTLSConfigName is the name of the default set of options for configuring TLS.
//	DefaultTLSConfigName = "default"
//	// DefaultTLSStoreName is the name of the default store of TLS certificates.
//	// Note that it actually is the only usable one for now.
//	DefaultTLSStoreName = "default"
//)
//
//// CertAndStore allows mapping a TLS certificate to a TLS store.
//type CertAndStore struct {
//	Certificate
//	Store string
//}
//
//// Certificate is a struct which contains all data needed from an ACME certificate.
//type Certificate struct {
//	Domain      string `json:"domain,omitempty" toml:"domain,omitempty" yaml:"domain,omitempty"`
//	Certificate []byte `json:"certificate,omitempty" toml:"certificate,omitempty" yaml:"certificate,omitempty"`
//	Key         []byte `json:"key,omitempty" toml:"key,omitempty" yaml:"key,omitempty"`
//}
//
//// Provider holds configurations of the provider.
//type Manager struct {
//	*Configuration
//	ResolverName string
//	Store        Store `json:"store,omitempty" toml:"store,omitempty" yaml:"store,omitempty"`
//
//	certificate    *CertAndStore
//	certificatesMu sync.RWMutex
//
//	account     *Account
//	client      *lego.Client
//	clientMutex sync.Mutex
//
//	DnsServerConfig *dnsserver.Config
//}
//
//// Configuration holds ACME configuration provided by users.
//type Configuration struct {
//	Email                string `description:"Email address used for registration." json:"email,omitempty" toml:"email,omitempty" yaml:"email,omitempty"`
//	CAServer             string `description:"CA server to use." json:"caServer,omitempty" toml:"caServer,omitempty" yaml:"caServer,omitempty"`
//	PreferredChain       string `description:"Preferred chain to use." json:"preferredChain,omitempty" toml:"preferredChain,omitempty" yaml:"preferredChain,omitempty" export:"true"`
//	Storage              string `description:"Storage to use." json:"storage,omitempty" toml:"storage,omitempty" yaml:"storage,omitempty" export:"true"`
//	KeyType              string `description:"KeyType used for generating certificate private key. Allow value 'EC256', 'EC384', 'RSA2048', 'RSA4096', 'RSA8192'." json:"keyType,omitempty" toml:"keyType,omitempty" yaml:"keyType,omitempty" export:"true"`
//	CertificatesDuration int    `description:"Certificates' duration in hours." json:"certificatesDuration,omitempty" toml:"certificatesDuration,omitempty" yaml:"certificatesDuration,omitempty" export:"true"`
//
//	DNSChallenge *DNSChallenge `description:"Activate DNS-01 Challenge." json:"dnsChallenge,omitempty" toml:"dnsChallenge,omitempty" yaml:"dnsChallenge,omitempty" label:"allowEmpty" file:"allowEmpty" export:"true"`
//}
//
//// DNSChallenge contains DNS challenge configuration.
//type DNSChallenge struct {
//	Provider                string   `description:"Use a DNS-01 based challenge provider rather than HTTPS." json:"provider,omitempty" toml:"provider,omitempty" yaml:"provider,omitempty" export:"true"`
//	DelayBeforeCheck        int      `description:"Assume DNS propagates after a delay in seconds rather than finding and querying nameservers." json:"delayBeforeCheck,omitempty" toml:"delayBeforeCheck,omitempty" yaml:"delayBeforeCheck,omitempty" export:"true"`
//	Resolvers               []string `description:"Use following DNS servers to resolve the FQDN authority." json:"resolvers,omitempty" toml:"resolvers,omitempty" yaml:"resolvers,omitempty"`
//	DisablePropagationCheck bool     `description:"Disable the DNS propagation checks before notifying ACME that the DNS challenge is ready. [not recommended]" json:"disablePropagationCheck,omitempty" toml:"disablePropagationCheck,omitempty" yaml:"disablePropagationCheck,omitempty" export:"true"`
//}
//
//func (m *Manager) Start(domain string) error {
//	log.Info("Starting ACME")
//	if len(m.Configuration.Storage) == 0 {
//		return errors.New("unable to initialize ACME provider with no storage location for the certificates")
//	}
//
//	if m.CertificatesDuration < 1 {
//		return errors.New("cannot manage certificates with duration lower than 1 hour")
//	}
//
//	log.Info("so far so good")
//	var err error
//	//m.account, err = m.Store.GetAccount(m.ResolverName)
//	//if err != nil {
//	//return fmt.Errorf("unable to get ACME account: %w", err)
//	//}
//
//	// Reset Account if caServer changed, thus registration URI can be updated
//	if m.account != nil && m.account.Registration != nil && !isAccountMatchingCaServer(m.account.Registration.URI, m.CAServer) {
//		log.Info("Account URI does not match the current CAServer. The account will be reset.")
//		m.account = nil
//	}
//	log.Info("so far so good")
//
//	m.certificatesMu.Lock()
//	m.certificate, err = m.Store.GetCert(m.ResolverName)
//	m.certificatesMu.Unlock()
//
//	if err != nil {
//		log.Info("Should handle this eventually")
//	}
//	log.Info("so far so good")
//
//	ctx := context.Background()
//
//	m.watchDomain(domain)
//	log.Info("so far so good")
//
//	renewPeriod, renewInterval := getCertificateRenewDurations(m.CertificatesDuration)
//	log.Debugf("Attempt to renew certificates %q before expiry and check every %q", renewPeriod, renewInterval)
//
//	m.renewCertificate(renewPeriod)
//	log.Info("so far so good")
//
//	ticker := time.NewTicker(renewInterval)
//	go func(ctx context.Context) {
//		for {
//			select {
//			case <-ticker.C:
//				m.renewCertificate(renewPeriod)
//			case <-ctx.Done():
//				ticker.Stop()
//				return
//			}
//		}
//	}(ctx)
//
//	return nil
//}
//
//func isAccountMatchingCaServer(accountURI, serverURI string) bool {
//
//	aru, err := url.Parse(accountURI)
//	if err != nil {
//		log.Info("Unable to parse account.Registration URL")
//		return false
//	}
//
//	cau, err := url.Parse(serverURI)
//	if err != nil {
//		log.Info("Unable to parse CAServer URL")
//		return false
//	}
//
//	return cau.Hostname() == aru.Hostname()
//}
//
//// ThrottleDuration returns the throttle duration.
//func (p *Manager) ThrottleDuration() time.Duration {
//	return 0
//}
//
//func (p *Manager) getClient() (*lego.Client, error) {
//	p.clientMutex.Lock()
//	defer p.clientMutex.Unlock()
//
//	ctx := context.Background()
//
//	if p.client != nil {
//		return p.client, nil
//	}
//
//	account, err := p.initAccount(ctx)
//	if err != nil {
//		return nil, err
//	}
//
//	//logger.Debug().Msg("Building ACME client...")
//
//	caServer := lego.LEDirectoryProduction
//	if len(p.CAServer) > 0 {
//		caServer = p.CAServer
//	}
//	//logger.Debug().Msg(caServer)
//
//	config := lego.NewConfig(account)
//	config.CADirURL = caServer
//	config.Certificate.KeyType = GetKeyType(p.KeyType)
//	config.UserAgent = fmt.Sprintf("coredns/%s", coremain.CoreVersion)
//
//	client, err := lego.NewClient(config)
//	if err != nil {
//		return nil, err
//	}
//
//	// New users will need to register; be sure to save it
//	if account.GetRegistration() == nil {
//		reg, errR := p.register(client)
//		if errR != nil {
//			return nil, errR
//		}
//
//		account.Registration = reg
//	}
//
//	// Save the account once before all the certificates generation/storing
//	// No certificate can be generated if account is not initialized
//	//err = p.Store.SaveAccount(p.ResolverName, account)
//	//if err != nil {
//	//return nil, err
//	//}
//
//	if len(p.DNSChallenge.Provider) > 0 {
//		log.Debugf("Using DNS Challenge provider: %s", p.DNSChallenge.Provider)
//
//		var provider challenge.Provider
//		provider, err = dns.NewDNSChallengeProviderByName(p.DNSChallenge.Provider)
//		if err != nil {
//			return nil, err
//		}
//
//		err = client.Challenge.SetDNS01Provider(provider,
//			dns01.CondOption(len(p.DNSChallenge.Resolvers) > 0, dns01.AddRecursiveNameservers(p.DNSChallenge.Resolvers)),
//			dns01.WrapPreCheck(func(domain, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
//				if p.DNSChallenge.DelayBeforeCheck > 0 {
//					log.Debugf("Delaying %d rather than validating DNS propagation now.", p.DNSChallenge.DelayBeforeCheck)
//					time.Sleep(time.Duration(p.DNSChallenge.DelayBeforeCheck))
//				}
//
//				if p.DNSChallenge.DisablePropagationCheck {
//					return true, nil
//				}
//
//				return check(fqdn, value)
//			}),
//		)
//		if err != nil {
//			return nil, err
//		}
//	}
//
//	p.client = client
//	return p.client, nil
//}
//
//func (p *Manager) initAccount(ctx context.Context) (*Account, error) {
//	if p.account == nil || len(p.account.Email) == 0 {
//		var err error
//		p.account, err = NewAccount(p.Email, p.KeyType)
//		if err != nil {
//			return nil, err
//		}
//	}
//
//	// Set the KeyType if not already defined in the account
//	if len(p.account.KeyType) == 0 {
//		p.account.KeyType = GetKeyType(p.KeyType)
//	}
//
//	return p.account, nil
//}
//
//func (p *Manager) register(client *lego.Client) (*registration.Resource, error) {
//	log.Info("Register...")
//	return client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
//}
//
//func (p *Manager) resolveDomain(domain string, tlsStore string) {
//	if domain == "" {
//		log.Debug("No domain parsed in provider ACME")
//		return
//	}
//
//	log.Debugf("Trying to challenge certificate for domain %s found in HostSNI rule", domain)
//
//	go func() {
//		dom, cert, err := p.resolveCertificate(domain, tlsStore)
//		if err != nil {
//			log.Error("Unable to obtain ACME certificate for domains")
//			return
//		}
//
//		err = p.addCertificateForDomain(dom, cert)
//		if err != nil {
//			log.Error("Error adding certificate for domains")
//		}
//	}()
//}
//
//func (p *Manager) watchDomain(domain string) {
//	go func() {
//		for {
//			validDomain, err := p.sanitizeDomain(domain)
//			if err != nil {
//				log.Error("domain validation")
//			}
//
//			//if p.certExists(validDomain) {
//			//logger.Debug().Msg("Default ACME certificate generation is not required.")
//			//continue
//			//}
//
//			go func() {
//				cert, err := p.resolveDefaultCertificate(validDomain)
//				if err != nil {
//					log.Error("Unable to obtain ACME certificate for domain")
//					return
//				}
//
//				err = p.addCertificateForDomain(validDomain, cert)
//				if err != nil {
//					log.Error("Error adding certificate for domain")
//				}
//			}()
//		}
//	}()
//}
//
//func (p *Manager) resolveDefaultCertificate(domain string) (*certificate.Resource, error) {
//	log.Debugf("Loading ACME certificate %s...", domain)
//
//	client, err := p.getClient()
//	if err != nil {
//		return nil, fmt.Errorf("cannot get ACME client %w", err)
//	}
//
//	domains := []string{domain}
//	request := certificate.ObtainRequest{
//		Domains:        domains,
//		Bundle:         true,
//		PreferredChain: p.PreferredChain,
//	}
//
//	cert, err := client.Certificate.Obtain(request)
//	if err != nil {
//		return nil, fmt.Errorf("unable to generate a certificate for the domains %v: %w", domains, err)
//	}
//	if cert == nil {
//		return nil, fmt.Errorf("unable to generate a certificate for the domains %v", domains)
//	}
//	if len(cert.Certificate) == 0 || len(cert.PrivateKey) == 0 {
//		return nil, fmt.Errorf("certificate for domains %v is empty: %v", domains, cert)
//	}
//
//	log.Debugf("Default certificate obtained for domains %+v", domains)
//
//	return cert, nil
//}
//
//func (p *Manager) resolveCertificate(domain string, tlsStore string) (string, *certificate.Resource, error) {
//	domain, err := p.sanitizeDomain(domain)
//	if err != nil {
//		return "", nil, err
//	}
//
//	client, err := p.getClient()
//	if err != nil {
//		return "", nil, fmt.Errorf("cannot get ACME client %w", err)
//	}
//
//	domains := []string{domain}
//	request := certificate.ObtainRequest{
//		Domains:        domains,
//		Bundle:         true,
//		PreferredChain: p.PreferredChain,
//	}
//
//	cert, err := client.Certificate.Obtain(request)
//	if err != nil {
//		return "", nil, fmt.Errorf("unable to generate a certificate for the domain %s: %w", domain, err)
//	}
//	if cert == nil {
//		return "", nil, fmt.Errorf("unable to generate a certificate for the domain %s", domain)
//	}
//	if len(cert.Certificate) == 0 || len(cert.PrivateKey) == 0 {
//		return "", nil, fmt.Errorf("certificate for domain %s is empty: %v", domain, cert)
//	}
//
//	log.Debugf("Certificates obtained for domain %s", domain)
//
//	return domain, cert, nil
//}
//
//// getCertificateRenewDurations returns renew durations calculated from the given certificatesDuration in hours.
//// The first (RenewPeriod) is the period before the end of the certificate duration, during which the certificate should be renewed.
//// The second (RenewInterval) is the interval between renew attempts.
//func getCertificateRenewDurations(certificatesDuration int) (time.Duration, time.Duration) {
//	switch {
//	case certificatesDuration >= 365*24: // >= 1 year
//		return 4 * 30 * 24 * time.Hour, 7 * 24 * time.Hour // 4 month, 1 week
//	case certificatesDuration >= 3*30*24: // >= 90 days
//		return 30 * 24 * time.Hour, 24 * time.Hour // 30 days, 1 day
//	case certificatesDuration >= 7*24: // >= 7 days
//		return 24 * time.Hour, time.Hour // 1 days, 1 hour
//	case certificatesDuration >= 24: // >= 1 days
//		return 6 * time.Hour, 10 * time.Minute // 6 hours, 10 minutes
//	default:
//		return 20 * time.Minute, time.Minute
//	}
//}
//
//func (p *Manager) renewCertificate(renewPeriod time.Duration) {
//	log.Info("Testing certificate renew...")
//
//	p.certificatesMu.RLock()
//	var cert CertAndStore
//	crt, err := getX509Certificate(&cert.Certificate)
//
//	// If there's an error, we assume the cert is broken, and needs update
//	if err != nil || crt == nil || crt.NotAfter.Before(time.Now().Add(renewPeriod)) {
//		log.Info("Cert needs to be renewed")
//	} else {
//		log.Info("Cert does not need to be renewed")
//		return
//	}
//	p.certificatesMu.RUnlock()
//
//	client, err := p.getClient()
//	if err != nil {
//		log.Infof("Error renewing certificate from LE : %+v", cert.Domain)
//	}
//
//	log.Infof("Renewing certificate from LE : %+v", cert.Domain)
//
//	res := certificate.Resource{
//		Domain:      cert.Domain,
//		PrivateKey:  cert.Key,
//		Certificate: cert.Certificate.Certificate,
//	}
//
//	opts := &certificate.RenewOptions{
//		Bundle:         true,
//		PreferredChain: p.PreferredChain,
//	}
//
//	renewedCert, err := client.Certificate.RenewWithOptions(res, opts)
//	if err != nil {
//		log.Errorf("Error renewing certificate from LE: %v", cert.Domain)
//	}
//
//	if len(renewedCert.Certificate) == 0 || len(renewedCert.PrivateKey) == 0 {
//		log.Errorf("domain %s renew certificate with no value: %v", cert.Domain, cert)
//	}
//
//	err = p.addCertificateForDomain(cert.Domain, renewedCert)
//	if err != nil {
//		log.Error("Error adding certificate for domain")
//	}
//}
//
//// sanitizeDomains checks if given domain is allowed to generate a ACME certificate and return it.
//func (p *Manager) sanitizeDomain(domain string) (string, error) {
//	if domain == "" {
//		return "", errors.New("no domain was given")
//	}
//
//	var cleanDomain string
//	if strings.HasPrefix(domain, "*.*") {
//		return "", fmt.Errorf("unable to generate a wildcard certificate in ACME provider for domain %s : ACME does not allow '*.*' wildcard domain", domain)
//	}
//
//	canonicalDomain := canonicalDomain(domain)
//	cleanDomain = dns01.UnFqdn(canonicalDomain)
//	if canonicalDomain != cleanDomain {
//		log.Warningf("FQDN detected, please remove the trailing dot: %s", canonicalDomain)
//	}
//
//	return cleanDomain, nil
//}
//
//// CanonicalDomain returns a lower case domain with trim space.
//func canonicalDomain(domain string) string {
//	return strings.ToLower(strings.TrimSpace(domain))
//}
//
//func getX509Certificate(cert *Certificate) (*x509.Certificate, error) {
//	tlsCert, err := tls.X509KeyPair(cert.Certificate, cert.Key)
//	if err != nil {
//		log.Error("Failed to load TLS key pair from ACME certificate for domain, certificate will be renewed")
//		return nil, err
//	}
//
//	crt := tlsCert.Leaf
//	if crt == nil {
//		crt, err = x509.ParseCertificate(tlsCert.Certificate[0])
//		if err != nil {
//			log.Error("Failed to parse TLS key pair from ACME certificate for domain, certificate will be renewed")
//		}
//	}
//
//	return crt, err
//}
//
//func (m *Manager) addCertificateForDomain(domain string, cert *certificate.Resource) error {
//	// Save the certificate and key to storage
//	err := m.Store.SaveCert(domain, cert.Certificate, cert.PrivateKey)
//	if err != nil {
//		return err
//	}
//
//	// Load the certificate from storage
//	certAndStore, err := m.Store.GetCert(domain)
//	if err != nil {
//		return err
//	}
//
//	// Create a new TLS certificate
//	tlsCert, err := tls.X509KeyPair(certAndStore.Certificate.Certificate, certAndStore.Certificate.Key)
//	if err != nil {
//		return err
//	}
//
//	m.DnsServerConfig.TLSConfig = &tls.Config{
//		Certificates: []tls.Certificate{tlsCert},
//	}
//
//	return nil
//}
