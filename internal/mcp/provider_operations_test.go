package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/testutil"
	"github.com/jpvelasco/nyx/internal/testutil/providerfixture"
)

func useInfoStub(s *Server) *Server {
	s.readInfo = func(ctx context.Context, op service.InfoOperation, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
		switch op.Provider {
		case "omada":
			i, err := s.omadaSvc.Info(ctx, service.OmadaOptions{Host: opts.Host, Site: opts.Site, ClientID: opts.ClientID, ClientSecret: opts.ClientSecret, CACertPath: opts.CACertPath, SkipTLSVerify: opts.SkipTLSVerify})
			if err != nil || i == nil {
				return nil, err
			}
			return &providers.ProviderInfo{Provider: i.Provider, Host: i.Host, Version: i.Version, Extra: map[string]string{"api_version": i.APIVersion, "omada_cid": i.OmadaCID}, Configured: i.Configured}, nil
		case "opnsense":
			i, err := s.opnsenseSvc.Info(ctx, service.OpnsenseOptions{Host: opts.Host, APIKey: opts.ClientID, APISecret: opts.ClientSecret, CACertPath: opts.CACertPath, SkipTLSVerify: opts.SkipTLSVerify})
			if err != nil || i == nil {
				return nil, err
			}
			return &providers.ProviderInfo{Provider: i.Provider, Host: i.Host, Version: i.Version, Extra: map[string]string{"product": i.Product, "arch": i.Arch}}, nil
		default:
			return op.Info(ctx, opts)
		}
	}
	return s
}

func TestThirdAdapterProtocol(t *testing.T) {
	hermeticCreds(t)
	providerfixture.IsolateProviders(t)
	adapter := new(providerfixture.ReadOnlyAdapter)
	if err := providers.Register(adapter); err != nil {
		t.Fatal(err)
	}
	s := NewServerWithLogger(nil)
	var out bytes.Buffer
	s.writer = &out
	s.reader = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"synthetic_get_info","arguments":{"host":"switch.example","api_key":"fixture-secret"}}}
`)
	if err := s.Serve(context.Background()); err != nil {
		t.Fatal(err)
	}
	var responses []jsonRPCResponse
	dec := json.NewDecoder(&out)
	for dec.More() {
		var r jsonRPCResponse
		if err := dec.Decode(&r); err != nil {
			t.Fatal(err)
		}
		responses = append(responses, r)
	}
	if len(responses) != 3 || adapter.Calls != 1 {
		t.Fatalf("responses=%d calls=%d", len(responses), adapter.Calls)
	}
	listed := toJSON(responses[1])
	if !strings.Contains(listed, "synthetic_get_info") || strings.Contains(listed, "synthetic_apply") {
		t.Fatal("incorrect discovery")
	}
	result := toJSON(responses[2])
	if !strings.Contains(result, "switch.example") || strings.Contains(result, "fixture-secret") {
		t.Fatal("invalid info response")
	}
}

func TestBuiltinRegisteredInfo(t *testing.T) {
	hermeticCreds(t)
	for _, tc := range []struct {
		name, path, body string
		want             map[string]interface{}
	}{
		{"omada", "/api/info", `{"errorCode":0,"result":{"controllerVer":"6.3","apiVer":"1","omadacId":"fixture","configured":true}}`, map[string]interface{}{"provider": "omada", "version": "6.3", "api_version": "1", "omada_cid": "fixture", "configured": true}},
		{"opnsense", "/api/diagnostics/system/system_information", `{"versions":["OPNsense 26.7.10-amd64"]}`, map[string]interface{}{"provider": "opnsense", "version": "26.7.10", "arch": "amd64", "product": "OPNsense"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != tc.path {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				testutil.WriteBody(w, tc.body)
			}))
			defer srv.Close()
			host := strings.TrimPrefix(srv.URL, "https://")
			server := NewServerWithLogger(nil)
			result, failed := server.dispatchTool(t.Context(), tc.name+"_get_info", map[string]interface{}{"host": host, "api_key": "key", "api_secret": "fixture-secret", "skip_tls_verify": true})
			var payload map[string]interface{}
			tc.want["host"] = host
			if err := json.Unmarshal([]byte(result), &payload); err != nil || failed || !reflect.DeepEqual(payload, tc.want) {
				t.Fatalf("registered info: got %v want %v reason %v failed %v", payload, tc.want, err, failed)
			}
		})
	}
}
