package tls

import (
	ctls "crypto/tls"
	"fmt"
	"strconv"
	"sync"
	"time"

	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/tls"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
)

func init() { plugin.Register("tls", setup) }

func setup(c *caddy.Controller) error {
	err := parseTLS(c)
	if err != nil {
		return plugin.Error("tls", err)
	}
	return nil
}

var (
	log            = clog.NewWithPlugin("tls")
	once, shutOnce sync.Once
)

// You'll need a user or account type that implements acme.User
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

const (
	defaultCA            = "https://acme-v02.api.letsencrypt.org/directory"
	defaultEmail         = "doesnotexist@test.com"
	defaultCheckInterval = 15
	defaultPort          = 53
	defaultCertPath      = "./.tls/"
)

func parseTLS(c *caddy.Controller) error {
	config := dnsserver.GetConfig(c)

	var tlsconf *ctls.Config
	var err error
	clientAuth := ctls.NoClientCert

	if config.TLSConfig != nil {
		return plugin.Error("tls", c.Errf("TLS already configured for this server instance"))
	}
	for c.Next() {
		args := c.RemainingArgs()

		if args[0] == "acme" {
			log.Debug("Starting ACME Setup")

			var email string
			var dnsProvider string
			delayBeforeCheck := 0
			resolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}
			disablePropagationCheck := false
			//preferredChain := "ISRG Root X1"
			caServer := lego.LEDirectoryStaging

			for c.NextBlock() {
				token := c.Val()
				switch token {
				case "email":
					emailArgs := c.RemainingArgs()
					if len(emailArgs) > 1 {
						return plugin.Error("tls", c.Errf("Too many arguments to email"))
					}
					email = emailArgs[0]
				case "dnsProvider":
					dnsProviderArgs := c.RemainingArgs()
					if len(dnsProviderArgs) > 1 {
						return plugin.Error("tls", c.Errf("Too many arguments to dnsProvider"))
					}
					dnsProvider = dnsProviderArgs[0]
				case "delayBeforeCheck":
					delayBeforeCheckArgs := c.RemainingArgs()
					if len(delayBeforeCheckArgs) > 1 {
						return plugin.Error("tls", c.Errf("Too many arguments to delayBeforeCheck"))
					}
					delayBeforeCheck, err = strconv.Atoi(delayBeforeCheckArgs[0])
					if err != nil {
						return plugin.Error("tls", c.Errf("delayBeforeCheck needs to be a number"))
					}
				case "disablePropagationCheck":
					disablePropagationCheckArgs := c.RemainingArgs()
					if len(disablePropagationCheckArgs) > 1 {
						return plugin.Error("tls", c.Errf("Too many arguments to disablePropagationCheck"))
					}
					disablePropagationCheck, err = strconv.ParseBool(disablePropagationCheckArgs[0])
					if err != nil {
						return plugin.Error("tls", c.Errf("disablePropagationCheck needs to be a boolean"))
					}
				case "resolvers":
					resolversArgs := c.RemainingArgs()
					if len(resolversArgs) > 1 {
						return plugin.Error("tls", c.Errf("Too many arguments to resolvers"))
					}
					resolvers = append(resolvers, resolversArgs[0])
				case "caServer":
					caServerArgs := c.RemainingArgs()
					if len(caServerArgs) > 1 {
						return plugin.Error("tls", c.Errf("Too many arguments to caServer"))
					}
					caServer = caServerArgs[0]
				default:
					return c.Errf("unknown argument to acme '%s'", token)
				}
			}

			privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				log.Fatal(err)
			}

			myUser := MyUser{
				Email: email,
				key:   privateKey,
			}

			config := lego.NewConfig(&myUser)

			// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
			config.CADirURL = caServer
			config.Certificate.KeyType = certcrypto.RSA2048

			// A client facilitates communication with the CA server.
			client, err := lego.NewClient(config)
			if err != nil {
				log.Fatal(err)
			}

			var provider challenge.Provider
			provider, err = dns.NewDNSChallengeProviderByName(dnsProvider)
			if err != nil {
				return err
			}

			err = client.Challenge.SetDNS01Provider(provider,
				dns01.CondOption(len(resolvers) > 0, dns01.AddRecursiveNameservers(resolvers)),
				dns01.WrapPreCheck(func(domain, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
					if delayBeforeCheck > 0 {
						//log.Debug().Msgf("Delaying %d rather than validating DNS propagation now.", delayBeforeCheck)
						time.Sleep(time.Duration(delayBeforeCheck))
					}

					if disablePropagationCheck {
						return true, nil
					}

					return check(fqdn, value)
				}),
			)
			if err != nil {
				return err
			}

			// New users will need to register
			reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
			if err != nil {
				log.Fatal(err)
			}
			myUser.Registration = reg

			request := certificate.ObtainRequest{
				Domains: []string{"coredns-acme.xyz"},
				Bundle:  true,
			}

			certificates, err := client.Certificate.Obtain(request)
			if err != nil {
				log.Fatal(err)
			}

			// Each certificate comes back with the cert bytes, the bytes of the client's
			// private key, and a certificate URL. SAVE THESE TO DISK.
			fmt.Printf("%#v\n", certificates)

			//config.TLSConfig = tlsconf

		} else {
			//No ACME part - plugin continues to work like the normal tls plugin
			if len(args) < 2 || len(args) > 3 {
				return plugin.Error("tls", c.ArgErr())
			}
			for c.NextBlock() {
				switch c.Val() {
				case "client_auth":
					authTypeArgs := c.RemainingArgs()
					if len(authTypeArgs) != 1 {
						return c.ArgErr()
					}
					switch authTypeArgs[0] {
					case "nocert":
						clientAuth = ctls.NoClientCert
					case "request":
						clientAuth = ctls.RequestClientCert
					case "require":
						clientAuth = ctls.RequireAnyClientCert
					case "verify_if_given":
						clientAuth = ctls.VerifyClientCertIfGiven
					case "require_and_verify":
						clientAuth = ctls.RequireAndVerifyClientCert
					default:
						return c.Errf("unknown authentication type '%s'", authTypeArgs[0])
					}
				default:
					return c.Errf("unknown option '%s'", c.Val())
				}
			}
			tlsconf, err = tls.NewTLSConfigFromArgs(args...)
			if err != nil {
				return err
			}
			tlsconf.ClientAuth = clientAuth
			// NewTLSConfigs only sets RootCAs, so we need to let ClientCAs refer to it.
			tlsconf.ClientCAs = tlsconf.RootCAs
			config.TLSConfig = tlsconf
		}
	}
	return nil
}