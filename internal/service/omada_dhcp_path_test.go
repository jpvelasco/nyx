package service

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestComposeDHCPPath_DumbSwitchAccessUplink(t *testing.T) {
	rep := composeDHCPPath(dhcpPathFacts{
		clientMAC: "aa:bb:cc:dd:ee:01",
		client:    &OmadaClient{MAC: "aa-bb-cc-dd-ee-01", NetworkName: "iot"},
		topo: []OmadaClientTopologyNode{
			{NodeType: "clientNode", MAC: "aa-bb-cc-dd-ee-01", SwitchMAC: "aa-bb-cc-dd-ee-10", SwitchPort: "8"},
		},
		ports: []OmadaSwitchPort{{
			Port: 8, SwitchMAC: "aa-bb-cc-dd-ee-10", NetworkMode: 1,
			NativeNetwork: "trusted", Tagged: []string{"iot", "gaming"},
		}},
		nets: []OmadaNetwork{
			{Name: "trusted", DHCPEnabled: true},
			{Name: "iot", DHCPEnabled: true, Isolated: true},
			{Name: "gaming", DHCPEnabled: true},
		},
	})
	if rep.Port == nil || rep.Port.Port != 8 {
		t.Fatalf("port = %+v, want managed port 8", rep.Port)
	}
	if !strings.Contains(rep.ManagedHop, "dumb") {
		t.Errorf("managed hop = %q, want dumb-switch note", rep.ManagedHop)
	}
	joined := strings.Join(rep.Verdicts, " | ")
	if !strings.Contains(joined, "dumb switch cannot preserve 802.1Q") {
		t.Errorf("verdicts = %v, want mixed-VLAN access uplink", rep.Verdicts)
	}
	if !strings.Contains(joined, "no lease") {
		t.Errorf("verdicts = %v, want no-lease candidate", rep.Verdicts)
	}
	if !strings.Contains(joined, "isolated") {
		t.Errorf("verdicts = %v, want isolated LAN", rep.Verdicts)
	}
}

func TestComposeDHCPPath_TrunkNativeMismatch(t *testing.T) {
	rep := composeDHCPPath(dhcpPathFacts{
		clientMAC: "aa:bb:cc:dd:ee:01",
		client:    &OmadaClient{MAC: "aa-bb-cc-dd-ee-01", NetworkName: "iot"},
		switchMAC: "aa-bb-cc-dd-ee-10",
		port:      3,
		ports: []OmadaSwitchPort{{
			Port: 3, SwitchMAC: "aa-bb-cc-dd-ee-10", NetworkMode: 0,
			NativeNetwork: "trusted", Tagged: []string{"iot"},
		}},
		nets: []OmadaNetwork{
			{Name: "trusted", DHCPEnabled: true},
			{Name: "iot", DHCPEnabled: true, DHCPGuard: true},
		},
		leases: []OmadaGatewayDHCPUser{{MAC: "aa-bb-cc-dd-ee-01", IP: "10.0.60.20", NetworkName: "iot"}},
	})
	joined := strings.Join(rep.Verdicts, " | ")
	if !strings.Contains(joined, "trunk native") {
		t.Errorf("verdicts = %v, want native≠client VLAN", rep.Verdicts)
	}
	if !strings.Contains(joined, "DHCP guard") {
		t.Errorf("verdicts = %v, want guard candidate", rep.Verdicts)
	}
	if rep.Client == nil || !rep.Client.HasLease {
		t.Errorf("client = %+v, want lease from gateway table", rep.Client)
	}
}

func TestComposeDHCPPath_RequiresSelector(t *testing.T) {
	_, err := NewOmadaService().DiagnoseDHCPPath(context.Background(), OmadaOptions{}, OmadaDHCPPathRequest{})
	if err == nil || !strings.Contains(err.Error(), "client_mac or switch_mac+port") {
		t.Errorf("err = %v, want selector required", err)
	}
}

func TestDiagnoseDHCPPath_FetchesAndComposes(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case r.URL.Path == "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case r.URL.Path == "/openapi/v1/abc123/sites/s1/networks/client":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"mac":"aa-bb-cc-dd-ee-01","name":"pc1","type":"wired"}]}`)
		case r.URL.Path == "/openapi/v1/abc123/sites/s1/setting/service/dhcp/user-list":
			writeOmadaEnvelope(w, 0, `{"totalRows":0,"data":[]}`)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/clients/") && strings.HasSuffix(r.URL.Path, "/client-link-topology"):
			writeOmadaEnvelope(w, 0, `[{"nodeType":"clientNode","clientNode":{"mac":"aa-bb-cc-dd-ee-01","upOswInfo":{"mac":"aa-bb-cc-dd-ee-10","port":"8"}}},{"nodeType":"deviceNode","deviceNode":{"mac":"aa-bb-cc-dd-ee-00","name":"GW-CORE","model":"gateway"}}]`)
		case strings.Contains(r.URL.Path, "/switches/ports/overview"):
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"port":8,"switchMac":"aa-bb-cc-dd-ee-10","networkMode":1,"nativeNetworkId":"n1","profileId":"p1"}]}`)
		case strings.Contains(r.URL.Path, "/lan-profiles"):
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"p1","name":"access-trusted","nativeNetworkId":"n1","tagNetworkIds":["n2"]}]}`)
		case strings.HasSuffix(r.URL.Path, "/lan-networks"):
			writeOmadaEnvelope(w, 0, `{"totalRows":2,"data":[
				{"id":"n1","name":"trusted","vlan":10,"gatewaySubnet":"10.0.10.1/24","dhcpSettingsVO":{"enable":false}},
				{"id":"n2","name":"iot","vlan":60,"gatewaySubnet":"10.0.60.1/24","isolation":true,"dhcpSettingsVO":{"enable":true}}]}`)
		case strings.Contains(r.URL.Path, "/dhcp/user-list"):
			writeOmadaEnvelope(w, 0, `{"totalRows":0,"data":[]}`)
		default:
			http.NotFound(w, r)
		}
	})
	rep, err := NewOmadaService().DiagnoseDHCPPath(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true,
	}, OmadaDHCPPathRequest{ClientMAC: "aa:bb:cc:dd:ee:01"})
	if err != nil {
		t.Fatalf("DiagnoseDHCPPath: %v", err)
	}
	if rep.Client == nil || !strings.Contains(strings.Join(rep.Verdicts, " "), "no lease") {
		t.Fatalf("report = %+v", rep)
	}
	if _, err := NewOmadaService().DiagnoseDHCPPath(context.Background(), OmadaOptions{
		Host: "https://127.0.0.1:1", ClientID: "a", ClientSecret: "b", SkipTLSVerify: true,
	}, OmadaDHCPPathRequest{ClientMAC: "aa:bb:cc:dd:ee:01"}); err == nil {
		t.Fatal("unreachable controller must fail on ports/networks")
	}
}

func TestComposeDHCPPath_EmptyManagedPath(t *testing.T) {
	rep := composeDHCPPath(dhcpPathFacts{switchMAC: "aa-bb-cc-dd-ee-10", port: 1})
	if len(rep.Verdicts) != 1 || !strings.Contains(rep.Verdicts[0], "PVID") {
		t.Errorf("verdicts = %v, want unmanaged-hop PVID fallback", rep.Verdicts)
	}
}

func TestComposeDHCPPath_UnknownClientAndRelay(t *testing.T) {
	rep := composeDHCPPath(dhcpPathFacts{
		clientMAC: "aa:bb:cc:dd:ee:99",
		ports: []OmadaSwitchPort{{
			Port: 1, SwitchMAC: "aa-bb-cc-dd-ee-10", NetworkMode: 0, NativeNetwork: "trusted",
		}},
		switchMAC: "aa-bb-cc-dd-ee-10",
		port:      1,
		nets:      []OmadaNetwork{{Name: "trusted", DHCPEnabled: true, DHCPL2Relay: true}},
		topo:      []OmadaClientTopologyNode{{SwitchPort: "x"}},
	})
	if rep.Client == nil || rep.Client.MAC != "aa:bb:cc:dd:ee:99" || rep.Client.HasLease {
		t.Errorf("unknown client = %+v", rep.Client)
	}
	if !strings.Contains(strings.Join(rep.Verdicts, " "), "L2 relay") {
		t.Errorf("verdicts = %v, want relay candidate", rep.Verdicts)
	}
}

func TestDHCPPathHelpers(t *testing.T) {
	if findClient(nil, "aa:bb") != nil || findPort(nil, "aa", 1) != nil || leaseForMAC(nil, "aa") != nil {
		t.Fatal("empty lookups must be nil")
	}
	if firstGatewayMAC(nil) != "" || firstGatewayMAC([]OmadaClientTopologyNode{{Name: "SW"}}) != "" {
		t.Fatal("no gateway MAC expected")
	}
	if involvedLANs(nil, nil, nil) != nil {
		t.Fatal("no LANs without selectors")
	}
}

func TestDiagnoseDHCPPath_ReadFailures(t *testing.T) {
	ctx := context.Background()
	req := OmadaDHCPPathRequest{SwitchMAC: "aa:bb:cc:dd:ee:01", Port: 1}

	t.Run("switch-ports fetch fails", func(t *testing.T) {
		st := omadaPortStateFresh()
		st.OverviewFailAfter = 1
		ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
		_, err := NewOmadaService().DiagnoseDHCPPath(ctx, omadaPortOpts(ts.URL), req)
		if err == nil || !strings.Contains(err.Error(), "listing switch ports") {
			t.Errorf("err = %v, want listing switch ports failure", err)
		}
	})

	t.Run("networks fetch fails after ports succeed", func(t *testing.T) {
		st := omadaPortStateFresh()
		st.NetworksFailAfter = 2
		ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
		_, err := NewOmadaService().DiagnoseDHCPPath(ctx, omadaPortOpts(ts.URL), req)
		if err == nil || !strings.Contains(err.Error(), "listing networks") {
			t.Errorf("err = %v, want listing networks failure", err)
		}
	})
}

func TestDiagnoseDHCPPath_GatewayUsersFailWarns(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case r.URL.Path == "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case r.URL.Path == "/openapi/v1/abc123/sites/s1/networks/client":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"mac":"aa-bb-cc-dd-ee-01","name":"pc1","type":"wired"}]}`)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/clients/") && strings.HasSuffix(r.URL.Path, "/client-link-topology"):
			writeOmadaEnvelope(w, 0, `[{"nodeType":"deviceNode","deviceNode":{"mac":"aa-bb-cc-dd-ee-00","name":"GW-CORE","model":"gateway"}}]`)
		case strings.Contains(r.URL.Path, "/switches/ports/overview"):
			writeOmadaEnvelope(w, 0, `{"totalRows":0,"data":[]}`)
		case strings.Contains(r.URL.Path, "/lan-profiles"):
			writeOmadaEnvelope(w, 0, `{"totalRows":0,"data":[]}`)
		case strings.HasSuffix(r.URL.Path, "/lan-networks"):
			writeOmadaEnvelope(w, 0, `{"totalRows":0,"data":[]}`)
		case strings.Contains(r.URL.Path, "/dhcp/user-list"):
			writeOmadaEnvelope(w, -33004, `{"detail":"site busy"}`)
		default:
			http.NotFound(w, r)
		}
	})
	rep, err := NewOmadaService().DiagnoseDHCPPath(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true,
	}, OmadaDHCPPathRequest{ClientMAC: "aa:bb:cc:dd:ee:01"})
	if err != nil {
		t.Fatalf("DiagnoseDHCPPath: %v, want warning not error", err)
	}
	if !strings.Contains(strings.Join(rep.Warnings, " "), "gateway leases unavailable") {
		t.Errorf("warnings = %v, want gateway lease failure warning", rep.Warnings)
	}
}

func TestComposeDHCPPath_LeaseInference(t *testing.T) {
	t.Run("lease fills missing network name", func(t *testing.T) {
		rep := composeDHCPPath(dhcpPathFacts{
			clientMAC: "aa:bb:cc:dd:ee:77",
			client:    &OmadaClient{MAC: "aa:bb:cc:dd:ee:77", IP: "10.0.20.5", Name: "pc"},
			leases:    []OmadaGatewayDHCPUser{{MAC: "aa:bb:cc:dd:ee:77", IP: "10.0.20.5", NetworkName: "personal"}},
		})
		if rep.Client == nil || rep.Client.NetworkName != "personal" || !rep.Client.HasLease {
			t.Errorf("client = %+v, want network name from lease and lease set", rep.Client)
		}
		if rep.Port != nil {
			t.Errorf("port = %+v, want nil without a managed selector", rep.Port)
		}
	})

	t.Run("observed IP implies lease without a gateway row", func(t *testing.T) {
		rep := composeDHCPPath(dhcpPathFacts{
			clientMAC: "aa:bb:cc:dd:ee:88",
			client:    &OmadaClient{MAC: "aa:bb:cc:dd:ee:88", IP: "10.0.20.9", Name: "pc9"},
			leases:    []OmadaGatewayDHCPUser{{MAC: "aa:bb:cc:dd:ee:01", IP: "10.0.60.20", NetworkName: "iot"}},
			topo:      []OmadaClientTopologyNode{{SwitchMAC: "aa-bb-cc-dd-ee-10", SwitchPort: "x"}},
		})
		if rep.Client == nil || !rep.Client.HasLease || rep.Client.NetworkName != "" {
			t.Errorf("client = %+v, want IP-implied lease with empty network name", rep.Client)
		}
		if rep.Port != nil {
			t.Errorf("port = %+v, want nil for a non-numeric topology port", rep.Port)
		}
	})
}

func TestDHCPPathVisibility(t *testing.T) {
	for _, state := range []string{"disabled", "unknown"} {
		v := dhcpPathVerdicts(&OmadaDHCPPathReport{LANs: []OmadaNetwork{{Name: "media", DHCPState: state}}})
		if len(v) != 1 || !strings.Contains(v[0], state) {
			t.Fatalf("state %q: %v", state, v)
		}
	}
}
