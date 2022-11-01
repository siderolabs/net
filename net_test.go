// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package net_test

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	talosnet "github.com/siderolabs/net"
)

func TestAddressContainsPort(t *testing.T) {
	assert.Equal(t, talosnet.AddressContainsPort("192.168.1.1:9021"), true)
	assert.Equal(t, talosnet.AddressContainsPort("node0:10001"), true)
	assert.Equal(t, talosnet.AddressContainsPort("node0.testdomain.io:10001"), true)
	assert.Equal(t, talosnet.AddressContainsPort("[2001:db8::1]:64321"), true)
	assert.Equal(t, talosnet.AddressContainsPort("[2001:db8:3:4:5:6:7:1]:64321"), true)

	assert.Equal(t, talosnet.AddressContainsPort("[2001:db8:3:4:5:6:7:1:bad]:64321"), false)
	assert.Equal(t, talosnet.AddressContainsPort("2001:db8:0::2000"), false)
	assert.Equal(t, talosnet.AddressContainsPort("fd00::169:254:2:53"), false)
	assert.Equal(t, talosnet.AddressContainsPort("[fd00::169:254:2:53]"), false)
	assert.Equal(t, talosnet.AddressContainsPort("::1"), false)
	assert.Equal(t, talosnet.AddressContainsPort("127.0.0.1"), false)
	assert.Equal(t, talosnet.AddressContainsPort("node0"), false)
	assert.Equal(t, talosnet.AddressContainsPort("node0.testdomain.io"), false)
}

func TestFormatAddress(t *testing.T) {
	assert.Equal(t, talosnet.FormatAddress("2001:db8::1"), "[2001:db8::1]")
	assert.Equal(t, talosnet.FormatAddress("[2001:db8::1]"), "[2001:db8::1]")
	assert.Equal(t, talosnet.FormatAddress("192.168.1.1"), "192.168.1.1")
	assert.Equal(t, talosnet.FormatAddress("alpha.beta.gamma.com"), "alpha.beta.gamma.com")
}

func TestFormatCIDR(t *testing.T) {
	ip4 := netip.MustParseAddr("192.168.1.1")
	cidr4 := netip.MustParsePrefix("192.168.0.0/16")

	ip6 := netip.MustParseAddr("2001:db8::1")
	cidr6 := netip.MustParsePrefix("2001:db8::/32")

	assert.Equal(t, talosnet.FormatCIDR(ip4, cidr4), "192.168.1.1/16")
	assert.Equal(t, talosnet.FormatCIDR(ip6, cidr6), "2001:db8::1/32")
}

//nolint:scopelint
func TestNthIPInNetwork(t *testing.T) {
	type args struct {
		network netip.Prefix
		n       int
	}

	tests := []struct { //nolint:govet
		name string
		args args
		want netip.Addr
	}{
		{
			name: "increment IPv4 by 1",
			args: args{
				network: netip.MustParsePrefix("10.96.0.0/24"),
				n:       1,
			},
			want: netip.MustParseAddr("10.96.0.1"),
		},
		{
			name: "increment IPv4 by 10",
			args: args{
				network: netip.MustParsePrefix("10.96.0.0/24"),
				n:       10,
			},
			want: netip.MustParseAddr("10.96.0.10"),
		},
		{
			name: "increment IPv6 by 1",
			args: args{
				network: netip.MustParsePrefix("2001:db8:a0b:12f0::1/16"),
				n:       1,
			},
			want: netip.MustParseAddr("2001:db8:a0b:12f0::2"),
		},
		{
			name: "increment IPv6 by 10",
			args: args{
				network: netip.MustParsePrefix("2001:db8:a0b:12f0::1/16"),
				n:       10,
			},
			want: netip.MustParseAddr("2001:db8:a0b:12f0::b"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := talosnet.NthIPInNetwork(tt.args.network, tt.args.n)
			if err != nil {
				t.Errorf("%s", err)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NthFromIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateEndpointURI(t *testing.T) {
	goodTests := []string{
		"http://216.22.102.222",
		"https://[2001:db8:abef::ffff]:65000",
		"https://[2001:db8::ffff]",
		"http://goethe.de",
	}

	for _, testEP := range goodTests {
		assert.Nil(t, talosnet.ValidateEndpointURI(testEP), "URI should be valid")
	}

	badTests := []string{
		"12.34.56.89:1234",                 // ipv4:port, no protocol
		"[2001:db8::1]:5040",               // ipv6:port, no protocol
		"hostA:65301",                      // host:port, no protocol
		"my.long.domain.name:10101",        // dns:port, no protocol
		"192.168.2.1",                      // IP without port
		"[2001:db8::1]",                    // IPv6 without port
		"kubernetes.io",                    // hostname without port
		"2001:db8:123:445:204",             // IPv6 without brackets
		"http://2001:db8:101:101::1:50000", // IPv6 URL without brackets
		"http://192.168.1.1:1020304",       // Port out of range
		"http://192.168.1.1:0",             // 0 Port
		"http://192.168.1.1:-1000",         // Negative Port
	}

	for _, testEP := range badTests {
		assert.NotNil(t, talosnet.ValidateEndpointURI(testEP), "URI should be invalid")
	}
}

func TestFilterIPs(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct { //nolint:govet
		name     string
		ips      []string
		cidrs    []string
		expected string
	}{
		{
			name: "v4 and v6",
			ips: []string{
				"10.3.4.6",
				"2001:db8::1",
			},
			cidrs: []string{
				"0.0.0.0/0",
				"::/0",
			},
			expected: "[10.3.4.6 2001:db8::1]",
		},
		{
			name: "negative",
			ips: []string{
				"10.3.4.6",
				"10.3.4.1",
				"172.20.0.1",
			},
			cidrs: []string{
				"10.0.0.0/8",
				"!10.3.4.1/32",
			},
			expected: "[10.3.4.6]",
		},
		{
			name: "bare IP",
			ips: []string{
				"10.3.4.6",
				"10.3.4.1",
				"172.20.0.1",
			},
			cidrs: []string{
				"10.0.0.0/8",
				"!10.3.4.1",
			},
			expected: "[10.3.4.6]",
		},
		{
			name: "duplicate match",
			ips: []string{
				"10.3.4.6",
				"172.20.0.1",
			},
			cidrs: []string{
				"10.0.0.0/8",
				"0.0.0.0/0",
			},
			expected: "[10.3.4.6 172.20.0.1]",
		},
	} {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ips := make([]netip.Addr, len(tt.ips))

			for i := range ips {
				ips[i] = netip.MustParseAddr(tt.ips[i])
			}

			result, err := talosnet.FilterIPs(ips, tt.cidrs)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, fmt.Sprintf("%s", result))
		})
	}
}

func TestSplitCIDRs(t *testing.T) {
	cidrs, err := talosnet.SplitCIDRs("192.168.0.3/24,fed0::1/64")
	require.NoError(t, err)

	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24"), netip.MustParsePrefix("fed0::/64")}, cidrs)
}

func TestNthIPInCIDRSet(t *testing.T) {
	addrs, err := talosnet.NthIPInCIDRSet([]netip.Prefix{netip.MustParsePrefix("192.168.0.0/24"), netip.MustParsePrefix("fed0::/64")}, 128)
	require.NoError(t, err)

	assert.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.0.128"), netip.MustParseAddr("fed0::80")}, addrs)
}
