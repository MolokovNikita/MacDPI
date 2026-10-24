package main

import "testing"

func TestStartupKeepsIndependentFullHTTPSResults(t *testing.T) {
	_, checks := selectStrategy(func(st Strategy, host string) serviceCheck {
		// Both handshakes work; only different profiles finish each site's body.
		complete := host == "www.youtube.com" && st.Name == "multisplit" || host == "discord.com" && st.Name == "tlsrec-split"
		return serviceCheck{Host: host, TLS: true, HTTPS: complete, Strategy: st.Name}
	})
	if len(checks) != 2 || !checks[0].HTTPS || !checks[1].HTTPS || checks[0].Strategy != "multisplit" || checks[1].Strategy != "tlsrec-split" {
		t.Fatalf("lost site-specific successful HTTPS profiles: %+v", checks)
	}
}

func TestPacketProfileForDiscordDoesNotBecomeGlobalStrategy(t *testing.T) {
	old := activePacketEngine.Swap(&packetEngine{})
	defer activePacketEngine.Store(old)
	best, checks := selectStrategy(func(st Strategy, host string) serviceCheck {
		return serviceCheck{Host: host, Strategy: st.Name, TLS: true, HTTPS: host == "www.youtube.com" && st.Name == "multisplit" || host == "discord.com" && st.Name == "flowseal-general"}
	})
	if best.Name != "multisplit" || checks[1].Strategy != "flowseal-general" || !checks[1].HTTPS {
		t.Fatal("packet profile leaked into global traffic", best, checks)
	}
	p := newStrategyPolicy()
	p.seed(checks)
	if first := p.candidates("discord.com", "192.0.2.1:443", best)[0].Name; first != "flowseal-general" {
		t.Fatal("verified packet profile not selected", first)
	}
	seen := map[string]bool{}
	for range 6 {
		used := p.candidates("discord.com", "192.0.2.1:443", best)[0]
		if seen[used.Name] {
			t.Fatal("packet profile cycle repeated", used.Name)
		}
		seen[used.Name] = true
		p.remember("discord.com", "192.0.2.1:443", used.Name)
		p.penalize("discord.com", "192.0.2.1:443", used, best)
	}
	p = newStrategyPolicy()
	candidates := p.candidates("discord.com", "192.0.2.1:443", best)
	p.advanceFailedWindow("discord.com", "192.0.2.1:443", candidates)
	if got := p.candidates("discord.com", "192.0.2.1:443", best)[0].Name; got != candidates[4].Name {
		t.Fatal("untried profiles starved after handshake failures", got)
	}
}
