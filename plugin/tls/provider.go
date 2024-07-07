package tls

import (
	"os"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"github.com/libdns/digitalocean"
	"github.com/libdns/duckdns"
	"github.com/libdns/hetzner"
	"github.com/libdns/ionos"
	"github.com/libdns/namecheap"
	"github.com/libdns/netlify"
)

func createDNSSolver(provider string) *certmagic.DNS01Solver {
	var dnsSolver *certmagic.DNS01Solver
	switch provider {
	case "digitalocean":
		dnsSolver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &digitalocean.Provider{
					APIToken: os.Getenv("DO_AUTH_TOKEN"),
				},
			},
		}
	case "cloudflare":
		dnsSolver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &cloudflare.Provider{
					APIToken: os.Getenv(""),
				},
			},
		}
	case "hetzner":
		dnsSolver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &hetzner.Provider{
					AuthAPIToken: os.Getenv(""),
				},
			},
		}
	case "netlify":
		dnsSolver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &netlify.Provider{
					PersonalAccessToken: os.Getenv(""),
				},
			},
		}
	case "namecheap":
		dnsSolver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &namecheap.Provider{
					APIKey:      os.Getenv(""),
					APIEndpoint: os.Getenv(""),
				},
			},
		}
	case "ionos":
		dnsSolver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &ionos.Provider{
					AuthAPIToken: os.Getenv(""),
				},
			},
		}
	case "duckdns":
		dnsSolver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &duckdns.Provider{
					APIToken:       os.Getenv(""),
					OverrideDomain: os.Getenv(""),
				},
			},
		}
	}

	return dnsSolver
}
