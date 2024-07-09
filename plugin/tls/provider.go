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
	"github.com/libdns/route53"
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
					APIToken: os.Getenv("CLOUDFLARE_AUTH_TOKEN"),
				},
			},
		}
	case "hetzner":
		dnsSolver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &hetzner.Provider{
					AuthAPIToken: os.Getenv("HETZNER_AUTH_TOKEN"),
				},
			},
		}
	case "netlify":
		dnsSolver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &netlify.Provider{
					PersonalAccessToken: os.Getenv("NETLIFY_AUTH_TOKEN"),
				},
			},
		}
	case "namecheap":
		dnsSolver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &namecheap.Provider{
					User:        os.Getenv("NAMECHEAP_USER"),
					ClientIP:    os.Getenv("NAMECHEAP_CLIENT_IP"),
					APIKey:      os.Getenv("NAMECHEAP_API_KEY"),
					APIEndpoint: os.Getenv("NAMECHEAP_API_ENDPOINT"),
				},
			},
		}
	case "ionos":
		dnsSolver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &ionos.Provider{
					AuthAPIToken: os.Getenv("IONOS_AUTH_TOKEN"),
				},
			},
		}
	case "duckdns":
		dnsSolver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &duckdns.Provider{
					APIToken:       os.Getenv("DUCKDNS_TOKEN"),
					OverrideDomain: os.Getenv("DUCKDNS_OVERRIDE_DOMAIN"),
				},
			},
		}
	case "route53":
		dnsSolver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &route53.Provider{
					Region:      os.Getenv("AWS_REGION"),
					Profile:     os.Getenv("AWS_PROFILE"),
					AccessKeyId: os.Getenv("AWS_ACCESS_KEY_ID"),
				},
			},
		}
	}

	return dnsSolver
}
