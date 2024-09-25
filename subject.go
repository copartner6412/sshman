package sshman

import (
	"errors"
	"fmt"

	"github.com/copartner6412/input/validate"
)

// Subject defines the methods required to represent a host for which a TLS certificate will be generated.
type Subject interface {
	// GetCountry returns the Country for the TLS certificate.
	GetUser() []string

	// GetDomain returns the domain for the TLS certificate.
	GetDomain() []string

	// GetHostname returns the hostname for the TLS certificate.
	GetHostname() string

	// GetIPv4 returns the IPv4 addresses to be included in the certificate.
	GetIPv4() []string

	// GetIPv6 returns the IPv6 addresses to be included in the certificate.
	GetIPv6() []string
}

func ValidateSubject(subject Subject) error {
	if subject == nil {
		return errors.New("nil subject")
	}

	users := subject.GetUser()
	domains := subject.GetDomain()
	hostname := subject.GetHostname()
	ipv4s := subject.GetIPv4()
	ipv6s := subject.GetIPv6()

	if users == nil {
		return errors.New("subject must contain at least one user")
	}

	if subject.GetDomain() == nil && subject.GetHostname() == "" && subject.GetIPv4() == nil && subject.GetIPv6() == nil {
		return errors.New("subject must contain at least one of the following: hostname, IPv4 address, IPv6 address, or domain name")
	}

	var errs []error

	for _, domain := range domains {
		if err := validate.Domain(domain, 0, 0); err != nil {
			errs = append(errs, fmt.Errorf("invalid domain name: %w", err))
		}
	}

	if hostname != "" {
		if err := validate.LinuxHostname(hostname, 0, 0); err != nil {
			errs = append(errs, fmt.Errorf("invalid hostname: %w", err))
		}
	}

	for _, ipv4 := range ipv4s {
		if err := validate.IP(ipv4, ""); err != nil {
			errs = append(errs, fmt.Errorf("invalid IPv4: %w", err))
		}
	}

	for _, ipv6 := range ipv6s {
		if err := validate.IP(ipv6, ""); err != nil {
			errs = append(errs, fmt.Errorf("invalid IPv6: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid subject: %w", errors.Join(errs...))
	}

	return nil
}
