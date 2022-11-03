// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package net provides functions extending standard library package `net`.
package net

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const minPortRange = 1

const maxPortRange = 65535

// FormatAddress checks that the address has a consistent format.
func FormatAddress(addr string) string {
	addr = strings.Trim(addr, "[]")

	if ip, err := netip.ParseAddr(addr); err == nil {
		// If this is an IPv6 address, encapsulate it in brackets
		if ip.Is6() {
			return "[" + ip.String() + "]"
		}

		return ip.String()
	}

	return addr
}

// FormatCIDR formats IP from the network as CIDR notation.
func FormatCIDR(ip netip.Addr, network netip.Prefix) string {
	return netip.PrefixFrom(ip, network.Bits()).String()
}

// AddressContainsPort checks to see if the supplied address contains both an address and a port.
// This will not catch every possible permutation, but it is a best-effort routine suitable for prechecking human-interactive parameters.
func AddressContainsPort(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}

	if strings.Contains(host, ":") {
		if _, err := netip.ParseAddr(host); err != nil {
			return false
		}
	}

	return true
}

// NthIPInNetwork takes an IPNet and returns the nth IP in it.
func NthIPInNetwork(network netip.Prefix, n int) (netip.Addr, error) {
	addr := network.Addr()

	for i := 0; i < n; i++ {
		addr = addr.Next()
	}

	if network.Contains(addr) {
		return addr, nil
	}

	return netip.Addr{}, errors.New("network does not contain enough IPs")
}

// SplitCIDRs parses list of CIDRs in a string separated by commas.
func SplitCIDRs(cidrList string) (out []netip.Prefix, err error) {
	for _, podCIDR := range strings.Split(cidrList, ",") {
		cidr, err := netip.ParsePrefix(podCIDR)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %q as a CIDR: %w", podCIDR, err)
		}

		cidr = cidr.Masked()

		out = append(out, cidr)
	}

	return out, nil
}

// NthIPInCIDRSet returns nth IP for each CIDR in the list.
func NthIPInCIDRSet(cidrList []netip.Prefix, offset int) (out []netip.Addr, err error) {
	for _, cidr := range cidrList {
		ip, err := NthIPInNetwork(cidr, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate offset %d from CIDR %s: %w", offset, cidr, err)
		}

		out = append(out, ip)
	}

	return out, nil
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

// ParseSubnetOrAddress parses a CIDR or an IP address, returning a netip.Prefix.
//
// If a bare IP address is passed, it's treated as a CIDR with either /32 or /128 prefix.
func ParseSubnetOrAddress(subnet string) (netip.Prefix, error) {
	network, err := netip.ParsePrefix(subnet)
	if err != nil {
		// attempt to parse as a bare IP
		ip, ipErr := netip.ParseAddr(subnet)
		if ipErr == nil {
			network = netip.PrefixFrom(ip, ip.BitLen())
		} else {
			return netip.Prefix{}, fmt.Errorf("failed to parse subnet: %w", err)
		}
	}

	return network, nil
}

// FilterIPs filters list of IPs with the list of subnets.
//
// Each subnet can be either regular match or negative match (if prefixed with '!').
//
//nolint:gocognit
func FilterIPs(ips []netip.Addr, cidrs []string) ([]netip.Addr, error) {
	var result []netip.Addr

	for _, subnet := range cidrs {
		positiveMatch := true

		if strings.HasPrefix(subnet, "!") {
			// negative CIDR
			subnet = subnet[1:]
			positiveMatch = false
		}

		network, err := ParseSubnetOrAddress(subnet)
		if err != nil {
			return nil, err
		}

		for _, ip := range ips {
			switch {
			case network.Contains(ip) && positiveMatch:
				// add IP to the list if not duplicate
				found := false

				for _, addr := range result {
					if addr == ip {
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
					if addr == ip {
						result = append(result[:i], result[i+1:]...)

						break
					}
				}
			}
		}
	}

	return result, nil
}

// FilterLocalNetIPs filters list of IPs with the local subnets (rfc1918, rfc4193).
func FilterLocalNetIPs(ips []netip.Addr) ([]netip.Addr, error) {
	localSubnets := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"}

	return FilterIPs(ips, localSubnets)
}
