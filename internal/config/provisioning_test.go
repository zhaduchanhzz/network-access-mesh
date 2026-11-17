package config

import (
	"strings"
	"testing"
)

func TestLoadProvisioning(t *testing.T) {
	good := map[string]string{
		"MG_PROVISION_HEADSCALE_DIGEST":  "sha256:" + strings.Repeat("d", 64),
		"MG_PROVISION_HEADSCALE_VERSION": "v0.29.7",
		"MG_PROVISION_NAMESERVERS":       "1.1.1.1, 9.9.9.9",
		"MG_PROVISION_EDGE_ADDR":         "10.249.0.2:443",
		"MG_PROBER_URL":                  "http://prober:8080",
	}
	env := func(over map[string]string) func(string) string {
		m := map[string]string{}
		for k, v := range good {
			m[k] = v
		}
		for k, v := range over {
			m[k] = v
		}
		return func(k string) string { return m[k] }
	}
	p, errs := LoadProvisioning("worker", "staging", env(nil))
	if len(errs) != 0 || !p.Enabled() || len(p.Nameservers) != 2 || p.DNSCheck != "resolve" || p.ProberURL == "" {
		t.Fatalf("good: %+v %v", p, errs)
	}
	if p, errs := LoadProvisioning("worker", "staging", func(string) string { return "" }); len(errs) != 0 || p.Enabled() {
		t.Fatalf("unset: %+v %v", p, errs)
	}
	for name, over := range map[string]map[string]string{
		"api process":         nil,
		"digest":              {"MG_PROVISION_HEADSCALE_DIGEST": "sha256:short"},
		"version":             {"MG_PROVISION_HEADSCALE_VERSION": "latest"},
		"nameservers":         {"MG_PROVISION_NAMESERVERS": "1.1.1.1,dns.example"},
		"no nameserver":       {"MG_PROVISION_NAMESERVERS": ""},
		"edge":                {"MG_PROVISION_EDGE_ADDR": "edge:443"},
		"prober":              {"MG_PROBER_URL": "http://user:pw@prober:8080/x"},
		"dns check":           {"MG_PROVISION_DNS_CHECK": "maybe"},
		"skip outside dev/ci": {"MG_PROVISION_DNS_CHECK": "skip"},
		"dns server":          {"MG_PROVISION_DNS_SERVER": "resolver.example:53"},
	} {
		service := "worker"
		if name == "api process" {
			service = "api"
		}
		_, errs := LoadProvisioning(service, "staging", env(over))
		if len(errs) == 0 {
			t.Errorf("%s: accepted", name)
		}
		for _, e := range errs {
			if strings.Contains(e.Error(), "user:pw") || strings.Contains(e.Error(), "dns.example") {
				t.Errorf("%s: the error repeats a value: %v", name, e)
			}
		}
	}
	if _, errs := LoadProvisioning("worker", "ci", env(map[string]string{"MG_PROVISION_DNS_CHECK": "skip"})); len(errs) != 0 {
		t.Fatalf("skip on ci: %v", errs)
	}
}
