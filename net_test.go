// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package net_test

import (
	"net"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	talosnet "github.com/talos-systems/net"
)

func TestEmpty(t *testing.T) {
	// added for accurate coverage estimation
	//
	// please remove it once any unit-test is added
	// for this package
}

func TestAddressContainsPort(t *testing.T) {
	assert.Equal(t, talosnet.AddressContainsPort("192.168.1.1:9021"), true)
	assert.Equal(t, talosnet.AddressContainsPort("node0:10001"), true)
	assert.Equal(t, talosnet.AddressContainsPort("node0.testdomain.io:10001"), true)
	assert.Equal(t, talosnet.AddressContainsPort("[2001:db8::1]:64321"), true)
	assert.Equal(t, talosnet.AddressContainsPort("[2001:db8:3:4:5:6:7:1]:64321"), true)

	assert.Equal(t, talosnet.AddressContainsPort("[2001:db8:3:4:5:6:7:1:bad]:64321"), false)
	assert.Equal(t, talosnet.AddressContainsPort("2001:db8:0::2000"), false)
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

//nolint: scopelint
func TestNthIPInNetwork(t *testing.T) {
	type args struct {
		network *net.IPNet
		n       int
	}

	tests := []struct {
		name string
		args args
		want net.IP
	}{
		{
			name: "increment IPv4 by 1",
			args: args{
				network: &net.IPNet{
					IP:   net.IP{10, 96, 0, 0},
					Mask: net.IPMask{255, 255, 255, 0},
				},
				n: 1,
			},
			want: net.IP{10, 96, 0, 1},
		},
		{
			name: "increment IPv4 by 10",
			args: args{
				network: &net.IPNet{
					IP:   net.IP{10, 96, 0, 0},
					Mask: net.IPMask{255, 255, 255, 0},
				},
				n: 10,
			},
			want: net.IP{10, 96, 0, 10},
		},
		{
			name: "increment IPv6 by 1",
			args: args{
				network: &net.IPNet{
					IP:   net.ParseIP("2001:db8:a0b:12f0::1"),
					Mask: net.IPMask{255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				},
				n: 1,
			},
			want: net.ParseIP("2001:db8:a0b:12f0::2"),
		},
		{
			name: "increment IPv6 by 10",
			args: args{
				network: &net.IPNet{
					IP:   net.ParseIP("2001:db8:a0b:12f0::1"),
					Mask: net.IPMask{255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				},
				n: 10,
			},
			want: net.ParseIP("2001:db8:a0b:12f0::b"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := talosnet.NthIPInNetwork(tt.args.network, tt.args.n)
			if err != nil {
				t.Errorf("%w", err)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NthFromIP() = %v, want %v", got, tt.want)
			}
		})
	}
}
