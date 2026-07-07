package platform

import "testing"

func TestDetectProfile(t *testing.T) {
	cases := []struct {
		name       string
		os         OSInfo
		wsType     string
		runtime    string
		want       string
	}{
		{"ubuntu nginx host", OSInfo{Distro: "Ubuntu"}, "nginx", "host", "ubuntu-nginx"},
		{"ubuntu apache host", OSInfo{Distro: "Ubuntu"}, "apache2", "host", "ubuntu-apache"},
		{"debian nginx host", OSInfo{Distro: "Debian GNU/Linux"}, "nginx", "host", "ubuntu-nginx"},
		{"centos nginx host", OSInfo{Distro: "CentOS Linux"}, "nginx", "host", "centos-nginx"},
		{"rocky nginx host", OSInfo{Distro: "Rocky Linux"}, "nginx", "host", "centos-nginx"},
		{"docker nginx", OSInfo{Distro: "Alpine"}, "nginx", "docker", "docker-nginx"},
		{"docker traefik", OSInfo{Distro: "Alpine"}, "traefik", "docker", "docker-traefik"},
		{"docker beats host distro", OSInfo{Distro: "Ubuntu"}, "nginx", "docker", "docker-nginx"},
		{"unknown combo", OSInfo{Distro: "Arch Linux"}, "nginx", "host", ""},
		{"empty webserver", OSInfo{Distro: "Ubuntu"}, "", "host", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DetectProfile(c.os, c.wsType, c.runtime)
			if got != c.want {
				t.Errorf("DetectProfile() = %q, want %q", got, c.want)
			}
		})
	}
}