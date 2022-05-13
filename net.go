// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package net provides functions extending standard library package `net`.
package net

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"inet.af/netaddr"
)

const minPortRange = 1

const maxPortRange = 65535

// IPAddrs finds and returns a list of non-loopback IP addresses of the
// current machine.
func IPAddrs() (ips []net.IP, err error) {
	ips = []net.IP{}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ipnet.IP.IsGlobalUnicast() && !ipnet.IP.IsLinkLocalUnicast() {
				ips = append(ips, ipnet.IP)
			}
		}
	}

	return ips, nil
}

// IPFilterFunc filters IP addresses.
//
// List of IPFilterFuncs is applied with AND logic: all filters should return true
// for the IP address to be included in the response.
type IPFilterFunc func(ip net.IP) bool

// IPFilter filters list of IP addresses by applying sequence of filters.
//
// If any of the filters returns false, address is skipped.
func IPFilter(addrs []net.IP, filters ...IPFilterFunc) (result []net.IP) {
	for _, addr := range addrs {
		skip := false

		for _, filter := range filters {
			if !filter(addr) {
				skip = true

				break
			}
		}

		if !skip {
			result = append(result, addr)
		}
	}

	return result
}

// FormatAddress checks that the address has a consistent format.
func FormatAddress(addr string) string {
	addr = strings.Trim(addr, "[]")

	if ip := net.ParseIP(addr); ip != nil {
		// If this is an IPv6 address, encapsulate it in brackets
		if ip.To4() == nil {
			return "[" + ip.String() + "]"
		}

		return ip.String()
	}

	return addr
}

// FormatCIDR formats IP from the network as CIDR notation.
func FormatCIDR(ip net.IP, network net.IPNet) string {
	ones, _ := network.Mask.Size()

	return fmt.Sprintf("%s/%d", ip, ones)
}

// AddressContainsPort checks to see if the supplied address contains both an address and a port.
// This will not catch every possible permutation, but it is a best-effort routine suitable for prechecking human-interactive parameters.
func AddressContainsPort(addr string) bool {
	if !strings.Contains(addr, ":") || strings.Contains(addr, "/") {
		return false
	}

	if ip := net.ParseIP(strings.Trim(addr, "[]")); ip != nil {
		return false
	}

	pieces := strings.Split(addr, ":")

	// Check to see if it parses as an IP _without_ the last (presumed) `:port`
	trimmedAddr := strings.TrimSuffix(addr, ":"+pieces[len(pieces)-1])

	if ip := net.ParseIP(strings.Trim(trimmedAddr, "[]")); ip != nil {
		// We appear to have a valid IP followed by `:port`
		return true
	}

	if len(pieces) > 2 {
		// No idea what this is, but it doesn't appear to be addr:port
		return false
	}

	// Looks like it is host:port
	return true
}

// NthIPInNetwork takes an IPNet and returns the nth IP in it.
func NthIPInNetwork(network *net.IPNet, n int) (net.IP, error) {
	ip := network.IP
	dst := make([]byte, len(ip))
	copy(dst, ip)

	for i := 0; i < n; i++ {
		for j := len(dst) - 1; j >= 0; j-- {
			dst[j]++

			if dst[j] > 0 {
				break
			}
		}
	}

	if network.Contains(dst) {
		return dst, nil
	}

	return nil, errors.New("network does not contain enough IPs")
}

// SplitCIDRs parses list of CIDRs in a string separated by commas.
func SplitCIDRs(cidrList string) (out []*net.IPNet, err error) {
	for _, podCIDR := range strings.Split(cidrList, ",") {
		_, cidr, err := net.ParseCIDR(podCIDR)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %q as a CIDR: %w", podCIDR, err)
		}

		out = append(out, cidr)
	}

	return out, nil
}

// NthIPInCIDRSet returns nth IP for each CIDR in the list.
func NthIPInCIDRSet(cidrList []*net.IPNet, offset int) (out []net.IP, err error) {
	for _, cidr := range cidrList {
		ip, err := NthIPInNetwork(cidr, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate offset %d from CIDR %s: %w", offset, cidr, err)
		}

		out = append(out, ip)
	}

	return out, nil
}

// DNSNames returns a default set of machine names. It includes the hostname,
// and FQDN if the kernel domain name is set. If the kernel domain name is not
// set, only the hostname is included in the set.
func DNSNames() (dnsNames []string, err error) {
	var (
		hostname   string
		domainname string
	)

	// Add the hostname.

	if hostname, err = os.Hostname(); err != nil {
		return nil, err
	}

	dnsNames = []string{hostname}

	// Add the domain name if it is set.

	if domainname, err = DomainName(); err != nil {
		return nil, err
	}

	if domainname != "" {
		dnsNames = append(dnsNames, fmt.Sprintf("%s.%s", hostname, domainname))
	}

	return dnsNames, nil
}

// DomainName returns the kernel domain name. If a domain name is not found, an
// empty string is returned.
func DomainName() (domainname string, err error) {
	var b []byte

	if b, err = ioutil.ReadFile("/proc/sys/kernel/domainname"); err != nil {
		return "", err
	}

	domainname = string(b)

	if domainname == "(none)\n" {
		return "", nil
	}

	return strings.TrimSuffix(domainname, "\n"), nil
}

// IsIPv6 indicates whether any IP address within the provided set is an IPv6
// address.
func IsIPv6(addrs ...net.IP) bool {
	for _, a := range addrs {
		if a == nil || a.IsLoopback() || a.IsUnspecified() {
			continue
		}

		if a.To4() == nil {
			if a.To16() != nil {
				return true
			}
		}
	}

	return false
}

// IsNonLocalIPv6 indicates whether provided address is non-local IPv6 address.
func IsNonLocalIPv6(in net.IP) bool {
	if in == nil || in.IsLoopback() || in.IsUnspecified() {
		return false
	}

	if in.To4() == nil && in.To16() != nil {
		return true
	}

	return false
}

// ValidateEndpointURI checks that an endpoint is valid.
// This is a more strict check that merely `url.Parse`, in that it requires such things as properly-ranged numeric ports and bracket-enclosed IPv6 addresses.
func ValidateEndpointURI(ep string) error {
	u, err := url.Parse(ep)
	if err != nil {
		return err
	}

	if strings.Count(u.Host, ":") > 2 {
		// More than two colon indicates that we must have an IPv6 address.
		// If we have an IPv6 address, it *must* be enclosed by brackets.
		if strings.Count(u.Host, "[") < 1 || strings.Count(u.Host, "]") < 1 {
			return fmt.Errorf("IPv6 addresses MUST be enclosed by square brackets")
		}
	}

	if u.Hostname() == "" {
		return fmt.Errorf("hostname must not be blank")
	}

	if u.Port() != "" {
		return validatePortNumber(u.Port())
	}

	return nil
}

func validatePortNumber(p string) error {
	portInt, err := strconv.Atoi(p)
	if err != nil {
		return fmt.Errorf("port number must be numeric")
	}

	if portInt < minPortRange || portInt > maxPortRange {
		return fmt.Errorf("port number must be between %d and %d", minPortRange, maxPortRange)
	}

	return nil
}

// ParseCIDR parses a CIDR-formatted IP address.
// Unlike the standard library version, this will return the IP address itself, rather than the bare IP and the network address.
// If no CIDR notation is supplied, the address is presumed to be on a solo network (/32 for IPv4 or /128 for IPv6).
// NOTE: Unlike rtnl.ParseCIDR, this allows network addresses, since in many
// places in the kubernetes ecosystem, the functionality of a "network address"
// is not used and improperly prevents the use of an entire range of IP
// addresses.
func ParseCIDR(in string) (*net.IPNet, error) {
	if AddressContainsPort(in) {
		return nil, fmt.Errorf("CIDR address %q must not contain a port", in)
	}

	// Strip any IPv6 brackets.
	in = strings.Map(func(r rune) rune {
		switch r {
		case '[':
			return rune(-1)
		case ']':
			return rune(-1)
		default:
			return r
		}
	}, in)

	// If we have no subnet, assume it is solo.
	if soloIP := net.ParseIP(in); soloIP != nil {
		if IsIPv6(soloIP) {
			in += "/128"
		} else {
			in += "/32"
		}
	}

	baseIP, cidr, err := net.ParseCIDR(in)
	if err != nil {
		return nil, err
	}

	cidr.IP = baseIP

	return cidr, nil
}

// IPPrefixFrom make netaddr.IPPrefix from cidr-address and netmask strings.
// address can be IP or CIDR (1.1.1.1 or 1.1.1.1/8 or 1.1.1.1/255.0.0.0)
// netmask can be IP or number (255.255.255.0 or 24 or empty).
func IPPrefixFrom(address, netmask string) (netaddr.IPPrefix, error) {
	cidr := strings.SplitN(address, "/", 2)
	if len(cidr) == 1 {
		address = cidr[0]
	} else {
		address = cidr[0]
		netmask = cidr[1]
	}

	ip, err := netaddr.ParseIP(address)
	if err != nil {
		return netaddr.IPPrefix{}, fmt.Errorf("failed to parse ip address: %w", err)
	}

	if netmask == "" {
		if ip.Is4() {
			netmask = "32"
		} else {
			netmask = "128"
		}
	}

	bits, err := strconv.Atoi(netmask)
	if err != nil {
		netmask, err := netaddr.ParseIP(netmask)
		if err != nil {
			return netaddr.IPPrefix{}, fmt.Errorf("failed to parse netmask: %w", err)
		}

		mask, _ := netmask.MarshalBinary() //nolint:errcheck // never fails
		bits, _ = net.IPMask(mask).Size()
	}

	if ip.Is4() && bits > 32 {
		return netaddr.IPPrefix{}, fmt.Errorf("failed netmask should be the same address family")
	}

	return netaddr.IPPrefixFrom(ip, uint8(bits)), nil
}

// FilterIPs filters list of IPs with the list of subnets.
//
// Each subnet can be either regular match or negative match (if prefixed with '!').
//
//nolint:gocognit
func FilterIPs(ips []net.IP, cidrs []string) ([]net.IP, error) {
	var result []net.IP

	for _, subnet := range cidrs {
		positiveMatch := true

		if strings.HasPrefix(subnet, "!") {
			// negative CIDR
			subnet = subnet[1:]
			positiveMatch = false
		}

		network, err := ParseCIDR(subnet)
		if err != nil {
			return nil, fmt.Errorf("failed to parse subnet: %w", err)
		}

		for _, ip := range ips {
			switch {
			case network.Contains(ip) && positiveMatch:
				// add IP to the list if not duplicate
				found := false

				for _, addr := range result {
					if addr.Equal(ip) {
						found = true

						break
					}
				}

				if !found {
					result = append(result, ip)
				}
			case network.Contains(ip) && !positiveMatch:
				// remote IP from the list
				for i, addr := range result {
					if addr.Equal(ip) {
						result = append(result[:i], result[i+1:]...)

						break
					}
				}
			}
		}
	}

	return result, nil
}
