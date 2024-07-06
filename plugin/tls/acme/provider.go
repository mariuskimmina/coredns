package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/coremain"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
)

const resolverSuffix = ".acme"

var log = clog.NewWithPlugin("tls")

// Configuration holds ACME configuration provided by users.
type Configuration struct {
	Email                string `description:"Email address used for registration." json:"email,omitempty" toml:"email,omitempty" yaml:"email,omitempty"`
	CAServer             string `description:"CA server to use." json:"caServer,omitempty" toml:"caServer,omitempty" yaml:"caServer,omitempty"`
	PreferredChain       string `description:"Preferred chain to use." json:"preferredChain,omitempty" toml:"preferredChain,omitempty" yaml:"preferredChain,omitempty" export:"true"`
	Storage              string `description:"Storage to use." json:"storage,omitempty" toml:"storage,omitempty" yaml:"storage,omitempty" export:"true"`
	KeyType              string `description:"KeyType used for generating certificate private key. Allow value 'EC256', 'EC384', 'RSA2048', 'RSA4096', 'RSA8192'." json:"keyType,omitempty" toml:"keyType,omitempty" yaml:"keyType,omitempty" export:"true"`
	EAB                  *EAB   `description:"External Account Binding to use." json:"eab,omitempty" toml:"eab,omitempty" yaml:"eab,omitempty"`
	CertificatesDuration int    `description:"Certificates' duration in hours." json:"certificatesDuration,omitempty" toml:"certificatesDuration,omitempty" yaml:"certificatesDuration,omitempty" export:"true"`

	DNSChallenge *DNSChallenge `description:"Activate DNS-01 Challenge." json:"dnsChallenge,omitempty" toml:"dnsChallenge,omitempty" yaml:"dnsChallenge,omitempty" label:"allowEmpty" file:"allowEmpty" export:"true"`
}

// SetDefaults sets the default values.
func (a *Configuration) SetDefaults() {
	a.CAServer = lego.LEDirectoryProduction
	a.Storage = "acme.json"
	a.KeyType = "RSA4096"
	a.CertificatesDuration = 3 * 30 * 24 // 90 Days
}

// CertAndStore allows mapping a TLS certificate to a TLS store.
type CertAndStore struct {
	Certificate
	Store string
}

// Certificate is a struct which contains all data needed from an ACME certificate.
type Certificate struct {
	Domain      Domain `json:"domain,omitempty" toml:"domain,omitempty" yaml:"domain,omitempty"`
	Certificate []byte `json:"certificate,omitempty" toml:"certificate,omitempty" yaml:"certificate,omitempty"`
	Key         []byte `json:"key,omitempty" toml:"key,omitempty" yaml:"key,omitempty"`
}

// EAB contains External Account Binding configuration.
type EAB struct {
	Kid         string `description:"Key identifier from External CA." json:"kid,omitempty" toml:"kid,omitempty" yaml:"kid,omitempty" loggable:"false"`
	HmacEncoded string `description:"Base64 encoded HMAC key from External CA." json:"hmacEncoded,omitempty" toml:"hmacEncoded,omitempty" yaml:"hmacEncoded,omitempty" loggable:"false"`
}

// DNSChallenge contains DNS challenge configuration.
type DNSChallenge struct {
	Provider                string   `description:"Use a DNS-01 based challenge provider rather than HTTPS." json:"provider,omitempty" toml:"provider,omitempty" yaml:"provider,omitempty" export:"true"`
	DelayBeforeCheck        Duration `description:"Assume DNS propagates after a delay in seconds rather than finding and querying nameservers." json:"delayBeforeCheck,omitempty" toml:"delayBeforeCheck,omitempty" yaml:"delayBeforeCheck,omitempty" export:"true"`
	Resolvers               []string `description:"Use following DNS servers to resolve the FQDN authority." json:"resolvers,omitempty" toml:"resolvers,omitempty" yaml:"resolvers,omitempty"`
	DisablePropagationCheck bool     `description:"Disable the DNS propagation checks before notifying ACME that the DNS challenge is ready. [not recommended]" json:"disablePropagationCheck,omitempty" toml:"disablePropagationCheck,omitempty" yaml:"disablePropagationCheck,omitempty" export:"true"`
}

// AcmeManager holds configurations of the provider.
type AcmeManager struct {
	lock sync.RWMutex

	*Configuration
	ResolverName string
	Store        Store `json:"store,omitempty" toml:"store,omitempty" yaml:"store,omitempty"`

	TLSChallengeProvider  challenge.Provider
	HTTPChallengeProvider challenge.Provider

	certificates   []*CertAndStore
	certificatesMu sync.RWMutex

	account           *Account
	client            *lego.Client
	configurationChan chan<- *TLSConfiguration
	//tlsManager             *traefiktls.Manager
	clientMutex            sync.Mutex
	configFromListenerChan chan TLSConfiguration
	resolvingDomains       map[string]struct{}
	resolvingDomainsMutex  sync.RWMutex
	stores                 map[string]*CertificateStore
}

// SetTLSManager sets the tls manager to use.
//func (p *Provider) SetTLSManager(tlsManager *traefiktls.Manager) {
//p.tlsManager = tlsManager
//}

// SetConfigListenerChan initializes the configFromListenerChan.
func (p *AcmeManager) SetConfigListenerChan(configFromListenerChan chan TLSConfiguration) {
	p.configFromListenerChan = configFromListenerChan
}

// ListenConfiguration sets a new Configuration into the configFromListenerChan.
func (p *AcmeManager) ListenConfiguration(config TLSConfiguration) {
	p.configFromListenerChan <- config
}

// Init for compatibility reason the BaseProvider implements an empty Init.
func (p *AcmeManager) Init() error {
	if len(p.Configuration.Storage) == 0 {
		return errors.New("unable to initialize ACME provider with no storage location for the certificates")
	}

	if p.CertificatesDuration < 1 {
		return errors.New("cannot manage certificates with duration lower than 1 hour")
	}

	var err error
	p.account, err = p.Store.GetAccount(p.ResolverName)
	if err != nil {
		return fmt.Errorf("unable to get ACME account: %w", err)
	}

	// Reset Account if caServer changed, thus registration URI can be updated
	if p.account != nil && p.account.Registration != nil && !isAccountMatchingCaServer(p.account.Registration.URI, p.CAServer) {
		log.Info("Account URI does not match the current CAServer. The account will be reset.")
		p.account = nil
	}

	p.certificatesMu.Lock()
	p.certificates, err = p.Store.GetCertificates(p.ResolverName)
	p.certificatesMu.Unlock()

	if err != nil {
		return fmt.Errorf("unable to get ACME certificates : %w", err)
	}

	// Init the currently resolved domain map
	p.resolvingDomains = make(map[string]struct{})

	return nil
}

func isAccountMatchingCaServer(accountURI, serverURI string) bool {

	aru, err := url.Parse(accountURI)
	if err != nil {
		log.Info("Unable to parse account.Registration URL")
		return false
	}

	cau, err := url.Parse(serverURI)
	if err != nil {
		log.Info("Unable to parse CAServer URL")
		return false
	}

	return cau.Hostname() == aru.Hostname()
}

// ThrottleDuration returns the throttle duration.
func (p *AcmeManager) ThrottleDuration() time.Duration {
	return 0
}

// Provide allows the file provider to provide configurations to traefik
// using the given Configuration channel.
func (p *AcmeManager) Provide(configurationChan chan<- *TLSConfiguration) error {
	log.Info("Starting to provide")
	ctx := context.Background()

	p.watchNewDomains(ctx)

	p.configurationChan = configurationChan

	log.Info("Moin")

	p.certificatesMu.RLock()
	msg := p.buildMessage()
	p.certificatesMu.RUnlock()

	log.Info("after buldMessage")

	log.Info(msg)

	p.configurationChan <- msg

	log.Info("after send msg")

	renewPeriod, renewInterval := getCertificateRenewDurations(p.CertificatesDuration)
	log.Debugf("Attempt to renew certificates %q before expiry and check every %q",
		renewPeriod, renewInterval)

	p.renewCertificates(renewPeriod)

	ticker := time.NewTicker(renewInterval)
	go func(ctxPool context.Context) {
		log.Info("Hello")
		for {
			select {
			case <-ticker.C:
				p.renewCertificates(renewPeriod)
			case <-ctxPool.Done():
				ticker.Stop()
				return
			}
		}
	}(ctx)

	return nil
}

func (p *AcmeManager) getClient() (*lego.Client, error) {
	p.clientMutex.Lock()
	defer p.clientMutex.Unlock()

	ctx := context.Background()

	if p.client != nil {
		return p.client, nil
	}

	account, err := p.initAccount(ctx)
	if err != nil {
		return nil, err
	}

	log.Debug("Building ACME client...")

	caServer := lego.LEDirectoryProduction
	if len(p.CAServer) > 0 {
		caServer = p.CAServer
	}
	log.Debug(caServer)

	config := lego.NewConfig(account)
	config.CADirURL = caServer
	config.Certificate.KeyType = GetKeyType(p.KeyType)
	config.UserAgent = fmt.Sprintf("containous-traefik/%s", coremain.CoreVersion)

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	// New users will need to register; be sure to save it
	if account.GetRegistration() == nil {
		reg, errR := p.register(client)
		if errR != nil {
			return nil, errR
		}

		account.Registration = reg
	}

	// Save the account once before all the certificates generation/storing
	// No certificate can be generated if account is not initialized
	err = p.Store.SaveAccount(p.ResolverName, account)
	if err != nil {
		return nil, err
	}

	if p.DNSChallenge == nil || len(p.DNSChallenge.Provider) == 0 {
		return nil, errors.New("ACME challenge not specified, please select TLS or HTTP or DNS Challenge")
	}

	if p.DNSChallenge != nil && len(p.DNSChallenge.Provider) > 0 {
		log.Debugf("Using DNS Challenge provider: %s", p.DNSChallenge.Provider)

		var provider challenge.Provider
		provider, err = dns.NewDNSChallengeProviderByName(p.DNSChallenge.Provider)
		if err != nil {
			return nil, err
		}

		err = client.Challenge.SetDNS01Provider(provider,
			dns01.CondOption(len(p.DNSChallenge.Resolvers) > 0, dns01.AddRecursiveNameservers(p.DNSChallenge.Resolvers)),
			dns01.WrapPreCheck(func(domain, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
				if p.DNSChallenge.DelayBeforeCheck > 0 {
					log.Debugf("Delaying %d rather than validating DNS propagation now.", p.DNSChallenge.DelayBeforeCheck)
					time.Sleep(time.Duration(p.DNSChallenge.DelayBeforeCheck))
				}

				if p.DNSChallenge.DisablePropagationCheck {
					return true, nil
				}

				return check(fqdn, value)
			}),
		)
		if err != nil {
			return nil, err
		}
	}

	p.client = client
	return p.client, nil
}

func (p *AcmeManager) initAccount(ctx context.Context) (*Account, error) {
	if p.account == nil || len(p.account.Email) == 0 {
		var err error
		p.account, err = NewAccount(p.Email, p.KeyType)
		if err != nil {
			return nil, err
		}
	}

	// Set the KeyType if not already defined in the account
	if len(p.account.KeyType) == 0 {
		p.account.KeyType = GetKeyType(p.KeyType)
	}

	return p.account, nil
}

func (p *AcmeManager) register(client *lego.Client) (*registration.Resource, error) {
	if p.EAB != nil {
		log.Info("Register with external account binding...")

		eabOptions := registration.RegisterEABOptions{TermsOfServiceAgreed: true, Kid: p.EAB.Kid, HmacEncoded: p.EAB.HmacEncoded}

		return client.Registration.RegisterWithExternalAccountBinding(eabOptions)
	}

	log.Info("Register...")

	return client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
}

func (p *AcmeManager) resolveDomains(domains []string, tlsStore string) {
	if len(domains) == 0 {
		log.Debug("No domain parsed in provider ACME")
		return
	}

	log.Debugf("Trying to challenge certificate for domain %v found in HostSNI rule", domains)

	var domain Domain
	if len(domains) > 0 {
		domain = Domain{Main: domains[0]}
		if len(domains) > 1 {
			domain.SANs = domains[1:]
		}

		go func() {
			dom, cert, err := p.resolveCertificate(domain, tlsStore)
			if err != nil {
				log.Error("Unable to obtain ACME certificate for domains")
				return
			}

			err = p.addCertificateForDomain(dom, cert, tlsStore)
			if err != nil {
				log.Error("Error adding certificate for domains", err)
			}
		}()
	}
}

func (p *AcmeManager) watchNewDomains(ctx context.Context) {
	log.Info("Watching a new domain")
	ctx = context.Background()

	go func(ctxPool context.Context) {
		for {
			select {
			case config := <-p.configFromListenerChan:
				log.Info("Heeeeeeeeeeeelllllllllllllo")
				log.Info(config)
				for tlsStoreName, tlsStore := range config.Stores {
					log.Info(tlsStoreName)

					if tlsStore.DefaultCertificate != nil && tlsStore.DefaultGeneratedCert != nil {
						log.Warning("defaultCertificate and defaultGeneratedCert cannot be defined at the same time.")
					}

					// Gives precedence to the user defined default certificate.
					if tlsStore.DefaultCertificate != nil || tlsStore.DefaultGeneratedCert == nil {
						continue
					}

					if tlsStore.DefaultGeneratedCert.Domain == nil || tlsStore.DefaultGeneratedCert.Resolver == "" {
						log.Warning("default generated certificate domain or resolver is missing.")
						continue
					}

					if tlsStore.DefaultGeneratedCert.Resolver != p.ResolverName {
						continue
					}

					validDomains, err := p.sanitizeDomains(*tlsStore.DefaultGeneratedCert.Domain)
					if err != nil {
						log.Error("domains validation", err)
					}

					if p.certExists(validDomains) {
						log.Debug("Default ACME certificate generation is not required.")
						continue
					}

					go func() {
						cert, err := p.resolveDefaultCertificate(validDomains)
						if err != nil {
							log.Error("Unable to obtain ACME certificate for domain", err)
							return
						}

						domain := Domain{
							Main: validDomains[0],
						}
						if len(validDomains) > 0 {
							domain.SANs = validDomains[1:]
						}

						err = p.addCertificateForDomain(domain, cert, DefaultTLSStoreName)
						if err != nil {
							log.Error("Error adding certificate for domain", err)
						}
					}()
				}
			case <-ctxPool.Done():
				return
			}
		}
	}(ctx)
}

func (p *AcmeManager) resolveDefaultCertificate(domains []string) (*certificate.Resource, error) {
	p.resolvingDomainsMutex.Lock()

	sort.Strings(domains)
	domainKey := strings.Join(domains, ",")

	if _, ok := p.resolvingDomains[domainKey]; ok {
		p.resolvingDomainsMutex.Unlock()
		return nil, nil
	}

	p.resolvingDomains[domainKey] = struct{}{}

	for _, certDomain := range domains {
		p.resolvingDomains[certDomain] = struct{}{}
	}

	p.resolvingDomainsMutex.Unlock()

	defer p.removeResolvingDomains(append(domains, domainKey))

	log.Debugf("Loading ACME certificates %+v...", domains)

	client, err := p.getClient()
	if err != nil {
		return nil, fmt.Errorf("cannot get ACME client %w", err)
	}

	request := certificate.ObtainRequest{
		Domains:        domains,
		Bundle:         true,
		PreferredChain: p.PreferredChain,
	}

	cert, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("unable to generate a certificate for the domains %v: %w", domains, err)
	}
	if cert == nil {
		return nil, fmt.Errorf("unable to generate a certificate for the domains %v", domains)
	}
	if len(cert.Certificate) == 0 || len(cert.PrivateKey) == 0 {
		return nil, fmt.Errorf("certificate for domains %v is empty: %v", domains, cert)
	}

	log.Debugf("Default certificate obtained for domains %+v", domains)

	return cert, nil
}

func (p *AcmeManager) resolveCertificate(domain Domain, tlsStore string) (Domain, *certificate.Resource, error) {
	domains, err := p.sanitizeDomains(domain)
	if err != nil {
		return Domain{}, nil, err
	}

	// Check if provided certificates are not already in progress and lock them if needed
	uncheckedDomains := p.getUncheckedDomains(domains, tlsStore)
	if len(uncheckedDomains) == 0 {
		return Domain{}, nil, nil
	}

	defer p.removeResolvingDomains(uncheckedDomains)

	log.Debug("Loading ACME certificates %+v...", uncheckedDomains)

	client, err := p.getClient()
	if err != nil {
		return Domain{}, nil, fmt.Errorf("cannot get ACME client %w", err)
	}

	request := certificate.ObtainRequest{
		Domains:        domains,
		Bundle:         true,
		PreferredChain: p.PreferredChain,
	}

	cert, err := client.Certificate.Obtain(request)
	if err != nil {
		return Domain{}, nil, fmt.Errorf("unable to generate a certificate for the domains %v: %w", uncheckedDomains, err)
	}
	if cert == nil {
		return Domain{}, nil, fmt.Errorf("unable to generate a certificate for the domains %v", uncheckedDomains)
	}
	if len(cert.Certificate) == 0 || len(cert.PrivateKey) == 0 {
		return Domain{}, nil, fmt.Errorf("certificate for domains %v is empty: %v", uncheckedDomains, cert)
	}

	log.Debugf("Certificates obtained for domains %+v", uncheckedDomains)

	domain = Domain{Main: uncheckedDomains[0]}
	if len(uncheckedDomains) > 1 {
		domain.SANs = uncheckedDomains[1:]
	}

	return domain, cert, nil
}

func (p *AcmeManager) removeResolvingDomains(resolvingDomains []string) {
	p.resolvingDomainsMutex.Lock()
	defer p.resolvingDomainsMutex.Unlock()

	for _, domain := range resolvingDomains {
		delete(p.resolvingDomains, domain)
	}
}

func (p *AcmeManager) addCertificateForDomain(domain Domain, crt *certificate.Resource, tlsStore string) error {
	if crt == nil {
		return nil
	}

	p.certificatesMu.Lock()
	defer p.certificatesMu.Unlock()

	cert := Certificate{Certificate: crt.Certificate, Key: crt.PrivateKey, Domain: domain}

	certUpdated := false
	for _, domainsCertificate := range p.certificates {
		if reflect.DeepEqual(domain, domainsCertificate.Certificate.Domain) {
			domainsCertificate.Certificate = cert
			certUpdated = true
			break
		}
	}

	if !certUpdated {
		p.certificates = append(p.certificates, &CertAndStore{Certificate: cert, Store: tlsStore})
	}

	p.configurationChan <- p.buildMessage()

	return p.Store.SaveCertificates(p.ResolverName, p.certificates)
}

// getCertificateRenewDurations returns renew durations calculated from the given certificatesDuration in hours.
// The first (RenewPeriod) is the period before the end of the certificate duration, during which the certificate should be renewed.
// The second (RenewInterval) is the interval between renew attempts.
func getCertificateRenewDurations(certificatesDuration int) (time.Duration, time.Duration) {
	switch {
	case certificatesDuration >= 365*24: // >= 1 year
		return 4 * 30 * 24 * time.Hour, 7 * 24 * time.Hour // 4 month, 1 week
	case certificatesDuration >= 3*30*24: // >= 90 days
		return 30 * 24 * time.Hour, 24 * time.Hour // 30 days, 1 day
	case certificatesDuration >= 7*24: // >= 7 days
		return 24 * time.Hour, time.Hour // 1 days, 1 hour
	case certificatesDuration >= 24: // >= 1 days
		return 6 * time.Hour, 10 * time.Minute // 6 hours, 10 minutes
	default:
		return 20 * time.Minute, time.Minute
	}
}

// deleteUnnecessaryDomains deletes from the configuration :
// - Duplicated domains
// - Domains which are checked by wildcard domain.
func deleteUnnecessaryDomains(domains []Domain) []Domain {
	var newDomains []Domain

	for idxDomainToCheck, domainToCheck := range domains {
		keepDomain := true

		for idxDomain, domain := range domains {
			if idxDomainToCheck == idxDomain {
				continue
			}

			if reflect.DeepEqual(domain, domainToCheck) {
				if idxDomainToCheck > idxDomain {
					log.Warningf("The domain %v is duplicated in the configuration but will be process by ACME provider only once.", domainToCheck)
					keepDomain = false
				}
				break
			}

			// Check if CN or SANS to check already exists
			// or can not be checked by a wildcard
			var newDomainsToCheck []string
			for _, domainProcessed := range domainToCheck.ToStrArray() {
				if idxDomain < idxDomainToCheck && isDomainAlreadyChecked(domainProcessed, domain.ToStrArray()) {
					// The domain is duplicated in a CN
					log.Warningf("Domain %q is duplicated in the configuration or validated by the domain %v. It will be processed once.", domainProcessed, domain)
					continue
				} else if domain.Main != domainProcessed && strings.HasPrefix(domain.Main, "*") && isDomainAlreadyChecked(domainProcessed, []string{domain.Main}) {
					// Check if a wildcard can validate the domain
					log.Warningf("Domain %q will not be processed by ACME provider because it is validated by the wildcard %q", domainProcessed, domain.Main)
					continue
				}
				newDomainsToCheck = append(newDomainsToCheck, domainProcessed)
			}

			// Delete the domain if both Main and SANs can be validated by the wildcard domain
			// otherwise keep the unchecked values
			if newDomainsToCheck == nil {
				keepDomain = false
				break
			}
			domainToCheck.Set(newDomainsToCheck)
		}

		if keepDomain {
			newDomains = append(newDomains, domainToCheck)
		}
	}

	return newDomains
}

func (p *AcmeManager) buildMessage() *TLSConfiguration {
	conf := &TLSConfiguration{}

	for _, cert := range p.certificates {
		certConf := &CertAndStores{
			TlsCertificate: TlsCertificate{
				CertFile: FileOrContent(cert.Certificate.Certificate),
				KeyFile:  FileOrContent(cert.Key),
			},
			Stores: []string{cert.Store},
		}
		conf.Certificates = append(conf.Certificates, certConf)
	}

	return conf
}

func (p *AcmeManager) renewCertificates(renewPeriod time.Duration) {
	log.Info("Testing certificate renew...")

	p.certificatesMu.RLock()

	var certificates []*CertAndStore
	for _, cert := range p.certificates {
		crt, err := getX509Certificate(&cert.Certificate)
		// If there's an error, we assume the cert is broken, and needs update
		if err != nil || crt == nil || crt.NotAfter.Before(time.Now().Add(renewPeriod)) {
			certificates = append(certificates, cert)
		}
	}

	p.certificatesMu.RUnlock()

	for _, cert := range certificates {
		client, err := p.getClient()
		if err != nil {
			log.Infof("Error renewing certificate from LE : %+v", cert.Domain)
			continue
		}

		log.Infof("Renewing certificate from LE : %+v", cert.Domain)

		res := certificate.Resource{
			Domain:      cert.Domain.Main,
			PrivateKey:  cert.Key,
			Certificate: cert.Certificate.Certificate,
		}

		opts := &certificate.RenewOptions{
			Bundle:         true,
			PreferredChain: p.PreferredChain,
		}

		renewedCert, err := client.Certificate.RenewWithOptions(res, opts)
		if err != nil {
			log.Errorf("Error renewing certificate from LE: %v", cert.Domain)
			continue
		}

		if len(renewedCert.Certificate) == 0 || len(renewedCert.PrivateKey) == 0 {
			log.Errorf("domains %v renew certificate with no value: %v", cert.Domain.ToStrArray(), cert)
			continue
		}

		err = p.addCertificateForDomain(cert.Domain, renewedCert, cert.Store)
		if err != nil {
			log.Error("Error adding certificate for domain")
		}
	}
}

// Get provided certificate which check a domains list (Main and SANs)
// from static and dynamic provided certificates.
func (p *AcmeManager) getUncheckedDomains(domainsToCheck []string, tlsStore string) []string {
	log.Debugf("Looking for provided certificate(s) to validate %q...", domainsToCheck)

	var allDomains []string
	store := p.GetStore(tlsStore)
	if store != nil {
		allDomains = append(allDomains, store.GetAllDomains()...)
	}

	// Get ACME certificates

	p.certificatesMu.RLock()
	for _, cert := range p.certificates {
		allDomains = append(allDomains, strings.Join(cert.Domain.ToStrArray(), ","))
	}
	p.certificatesMu.RUnlock()

	p.resolvingDomainsMutex.Lock()
	defer p.resolvingDomainsMutex.Unlock()

	// Get currently resolved domains
	for domain := range p.resolvingDomains {
		allDomains = append(allDomains, domain)
	}

	uncheckedDomains := searchUncheckedDomains(domainsToCheck, allDomains)

	// Lock domains that will be resolved by this routine
	for _, domain := range uncheckedDomains {
		p.resolvingDomains[domain] = struct{}{}
	}

	return uncheckedDomains
}

func searchUncheckedDomains(domainsToCheck, existentDomains []string) []string {
	var uncheckedDomains []string
	for _, domainToCheck := range domainsToCheck {
		if !isDomainAlreadyChecked(domainToCheck, existentDomains) {
			uncheckedDomains = append(uncheckedDomains, domainToCheck)
		}
	}

	if len(uncheckedDomains) == 0 {
		log.Debug("No ACME certificate generation required for domains")
	} else {
		log.Debugf("Domains need ACME certificates generation for domains %q.", strings.Join(uncheckedDomains, ","))
	}
	return uncheckedDomains
}

func getX509Certificate(cert *Certificate) (*x509.Certificate, error) {
	tlsCert, err := tls.X509KeyPair(cert.Certificate, cert.Key)
	if err != nil {
		log.Errorf("Failed to load TLS key pair from ACME certificate for domain, certificate will be renewed err: %v", err)
		return nil, err
	}

	crt := tlsCert.Leaf
	if crt == nil {
		crt, err = x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			log.Error("Failed to parse TLS key pair from ACME certificate for domain, certificate will be renewed")
		}
	}

	return crt, err
}

// sanitizeDomains checks if given domain is allowed to generate a ACME certificate and return it.
func (p *AcmeManager) sanitizeDomains(domain Domain) ([]string, error) {
	domains := domain.ToStrArray()
	if len(domains) == 0 {
		return nil, errors.New("no domain was given")
	}

	var cleanDomains []string
	for _, dom := range domains {
		if strings.HasPrefix(dom, "*.*") {
			return nil, fmt.Errorf("unable to generate a wildcard certificate in ACME provider for domain %q : ACME does not allow '*.*' wildcard domain", strings.Join(domains, ","))
		}

		canonicalDomain := CanonicalDomain(dom)
		cleanDomain := dns01.UnFqdn(canonicalDomain)
		if canonicalDomain != cleanDomain {
			log.Warningf("FQDN detected, please remove the trailing dot: %s", canonicalDomain)
		}

		cleanDomains = append(cleanDomains, cleanDomain)
	}

	return cleanDomains, nil
}

// certExists returns whether a certificate already exists for given domains.
func (p *AcmeManager) certExists(validDomains []string) bool {
	p.certificatesMu.RLock()
	defer p.certificatesMu.RUnlock()

	sort.Strings(validDomains)

	for _, cert := range p.certificates {
		domains := cert.Certificate.Domain.ToStrArray()
		sort.Strings(domains)
		if reflect.DeepEqual(domains, validDomains) {
			return true
		}
	}

	return false
}

func isDomainAlreadyChecked(domainToCheck string, existentDomains []string) bool {
	for _, certDomains := range existentDomains {
		for _, certDomain := range strings.Split(certDomains, ",") {
			if MatchDomain(domainToCheck, certDomain) {
				return true
			}
		}
	}
	return false
}
