package acme

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type CertStorage struct {
	dir     string
	storage map[string]CertAndStore
	mu      sync.RWMutex
}

// NewCertStorage initializes the CertStorage and loads existing certificates from disk.
func NewCertStorage(dir string) *CertStorage {
	cs := &CertStorage{
		dir:     dir,
		storage: make(map[string]CertAndStore),
	}
	// Load existing certificates from disk into memory
	if err := cs.loadFromDisk(); err != nil {
		log.Fatalf("Failed to load certificates from disk: %v", err)
	}
	return cs
}

// loadFromDisk loads existing certificates from the disk into memory.
func (cs *CertStorage) loadFromDisk() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Read all files in the directory
	files, err := os.ReadDir(cs.dir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if !file.IsDir() {
			path := filepath.Join(cs.dir, file.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			// Assume the filename format is "domain.crt" for certificate and "domain.key" for key
			ext := filepath.Ext(file.Name())
			domain := file.Name()[0 : len(file.Name())-len(ext)]
			certStore, exists := cs.storage[domain]
			if !exists {
				certStore = CertAndStore{Store: cs.dir}
			}
			if ext == ".crt" {
				certStore.Certificate.Certificate = data
				certStore.Certificate.Domain = domain
			} else if ext == ".key" {
				certStore.Certificate.Key = data
			}
			cs.storage[domain] = certStore
		}
	}
	return nil
}

// SaveCert saves a certificate and its key to the disk and updates the in-memory storage.
func (cs *CertStorage) SaveCert(domain string, certData, keyData []byte) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	certPath := filepath.Join(cs.dir, domain+".crt")
	keyPath := filepath.Join(cs.dir, domain+".key")

	err := os.WriteFile(certPath, certData, 0600)
	if err != nil {
		return err
	}
	err = os.WriteFile(keyPath, keyData, 0600)
	if err != nil {
		return err
	}

	cs.storage[domain] = CertAndStore{
		Certificate: Certificate{
			Domain:      domain,
			Certificate: certData,
			Key:         keyData,
		},
		Store: cs.dir,
	}

	return nil
}

// GetCert retrieves a specific certificate from the in-memory storage.
func (cs *CertStorage) GetCert(domain string) (*CertAndStore, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	certAndStore, ok := cs.storage[domain]
	if !ok {
		return nil, fmt.Errorf("certificate not found")
	}
	return &certAndStore, nil
}

// GetCerts retrieves all certificates from the in-memory storage.
func (cs *CertStorage) GetCerts() map[string]CertAndStore {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	certs := make(map[string]CertAndStore)
	for domain, certAndStore := range cs.storage {
		certs[domain] = certAndStore
	}
	return certs
}
