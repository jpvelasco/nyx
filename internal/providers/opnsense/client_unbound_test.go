package opnsense

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestGetUnboundSettings(t *testing.T) {
	t.Run("enabled interfaces and hosts", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/unbound/settings/get" {
				t.Errorf("path = %s", r.URL.Path)
			}
			testutil.WriteBody(w, `{"unbound":{"enable":"1","active_interface":{"lan":{"selected":1},"wan":{"selected":0}},"hosts":{"h1":{"hostname":"printer","domain":"home.example","server":"10.0.10.20"}}}}`)
		}))
		got, err := c.GetUnboundSettings(context.Background())
		if err != nil {
			t.Fatalf("GetUnboundSettings: %v", err)
		}
		if !got.Enabled || len(got.Interfaces) != 1 || got.Interfaces[0] != "lan" {
			t.Fatalf("settings = %+v", got)
		}
		if len(got.Hosts) != 1 || got.Hosts[0].Hostname != "printer" || got.Hosts[0].IP != "10.0.10.20" || got.Hosts[0].Domain != "home.example" {
			t.Fatalf("hosts = %+v", got.Hosts)
		}
	})
	t.Run("general wrapper", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"unbound":{"general":{"enabled":"1","interface":{"lan":{"selected":1}}}}}`)
		}))
		got, err := c.GetUnboundSettings(context.Background())
		if err != nil || !got.Enabled || len(got.Interfaces) != 1 || got.Interfaces[0] != "lan" {
			t.Fatalf("general = %+v %v", got, err)
		}
	})
	t.Run("403", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		_, err := c.GetUnboundSettings(context.Background())
		if err == nil || !isPermissionDenied(err) {
			t.Errorf("error = %v, want permission-denied", err)
		}
	})
	t.Run("404", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		_, err := c.GetUnboundSettings(context.Background())
		if err == nil || !isNotFound(err) {
			t.Errorf("error = %v, want not-found", err)
		}
	})
	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `not json`)
		}))
		_, err := c.GetUnboundSettings(context.Background())
		if err == nil || !strings.Contains(err.Error(), "decoding unbound settings") {
			t.Errorf("error = %v", err)
		}
	})
}

func TestGetUnboundHostOverrides(t *testing.T) {
	t.Run("camelCase", func(t *testing.T) {
		var seen []string
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = append(seen, r.URL.Path)
			if strings.Contains(r.URL.Path, "searchHostOverride") {
				testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"h1","hostname":"nas","domain":"home.example","server":"10.0.40.10"}]}`)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		got, err := c.GetUnboundHostOverrides(context.Background())
		if err != nil || len(got) != 1 || got[0].Hostname != "nas" || got[0].IP != "10.0.40.10" {
			t.Fatalf("got %+v %v", got, err)
		}
		if len(seen) == 0 || !strings.Contains(seen[0], "searchHostOverride") {
			t.Errorf("probe order = %v", seen)
		}
	})
	t.Run("snake_case fallback", func(t *testing.T) {
		var seen []string
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = append(seen, r.URL.Path)
			if strings.Contains(r.URL.Path, "search_host_override") {
				testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"h2","host":"printer","domain":"home.example","ip":"10.0.10.20"}]}`)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		got, err := c.GetUnboundHostOverrides(context.Background())
		if err != nil || len(got) != 1 || got[0].Hostname != "printer" || got[0].IP != "10.0.10.20" {
			t.Fatalf("got %+v %v", got, err)
		}
		joined := strings.Join(seen, ",")
		if !strings.Contains(joined, "searchHostOverride") || !strings.Contains(joined, "search_host_override") {
			t.Errorf("probe order = %v", seen)
		}
	})
	t.Run("403", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		_, err := c.GetUnboundHostOverrides(context.Background())
		if err == nil || !isPermissionDenied(err) {
			t.Errorf("error = %v, want permission-denied", err)
		}
	})
	t.Run("skips malformed", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"total":3,"rows":["x",{"uuid":""},{"uuid":"ok","hostname":"cam","server":"10.0.60.8"}]}`)
		}))
		got, err := c.GetUnboundHostOverrides(context.Background())
		if err != nil || len(got) != 1 || got[0].UUID != "ok" {
			t.Fatalf("got %+v %v", got, err)
		}
	})
}

func TestGetUnboundServiceStatus(t *testing.T) {
	t.Run("running bool", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/unbound/service/status" {
				t.Errorf("path = %s", r.URL.Path)
			}
			testutil.WriteBody(w, `{"running":true}`)
		}))
		ok, err := c.GetUnboundServiceStatus(context.Background())
		if err != nil || !ok {
			t.Fatalf("status = %v %v", ok, err)
		}
	})
	t.Run("status string", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"unbound":"running"}`)
		}))
		ok, err := c.GetUnboundServiceStatus(context.Background())
		if err != nil || !ok {
			t.Fatalf("got %v %v", ok, err)
		}
	})
	t.Run("ok string", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"status":"OK"}`)
		}))
		ok, err := c.GetUnboundServiceStatus(context.Background())
		if err != nil || !ok {
			t.Fatalf("got %v %v", ok, err)
		}
	})
	t.Run("stopped", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"running":false}`)
		}))
		ok, err := c.GetUnboundServiceStatus(context.Background())
		if err != nil || ok {
			t.Fatalf("got %v %v", ok, err)
		}
	})
	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `not json`)
		}))
		if _, err := c.GetUnboundServiceStatus(context.Background()); err == nil || !strings.Contains(err.Error(), "decoding unbound service status") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("404", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		if _, err := c.GetUnboundServiceStatus(context.Background()); err == nil {
			t.Fatal("expected 404")
		}
	})
}

func TestGetUnboundObserve(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "settings/get"):
				testutil.WriteBody(w, `{"unbound":{"enable":"1","interface":{"lan":{"selected":1}}}}`)
			case strings.Contains(r.URL.Path, "searchHostOverride"):
				testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"h1","hostname":"nas","domain":"home.example","server":"10.0.40.10"}]}`)
			case strings.Contains(r.URL.Path, "service/status"):
				testutil.WriteBody(w, `{"status":"running"}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		got, err := c.GetUnboundObserve(context.Background())
		if err != nil || !got.Enabled || !got.Running || len(got.Hosts) != 1 || got.Hosts[0].IP != "10.0.40.10" {
			t.Fatalf("observe = %+v %v", got, err)
		}
	})
	t.Run("search 404 keeps settings hosts", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "settings/get"):
				testutil.WriteBody(w, `{"unbound":{"enable":"1","hosts":{"h1":{"hostname":"printer","domain":"home.example","ip":"10.0.10.20"}}}}`)
			case strings.Contains(r.URL.Path, "service/status"):
				testutil.WriteBody(w, `{"running":true}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		got, err := c.GetUnboundObserve(context.Background())
		if err != nil || len(got.Hosts) != 1 || got.Hosts[0].Hostname != "printer" || !got.Running {
			t.Fatalf("observe = %+v %v", got, err)
		}
	})
	t.Run("403", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		if _, err := c.GetUnboundObserve(context.Background()); err == nil || !isPermissionDenied(err) {
			t.Fatal("expected 403")
		}
	})
}

func TestUnboundWrites(t *testing.T) {
	var posts []string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts = append(posts, r.URL.Path)
		}
		switch {
		case strings.Contains(r.URL.Path, "addHostOverride"):
			testutil.WriteBody(w, `{"result":"saved","uuid":"h-new"}`)
		case strings.Contains(r.URL.Path, "setHostOverride"), strings.Contains(r.URL.Path, "delHostOverride"), strings.Contains(r.URL.Path, "reconfigure"):
			testutil.WriteBody(w, `{"result":"saved"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	id, err := c.CreateUnboundOverride(context.Background(), UnboundHostWrite{Hostname: "nas", Domain: "home.example", IP: "10.0.40.10"})
	if err != nil || id != "h-new" {
		t.Fatalf("create = %q %v", id, err)
	}
	if err := c.SetUnboundOverride(context.Background(), "h1", UnboundHostWrite{Hostname: "nas", Domain: "home.example", IP: "10.0.40.11"}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteUnboundOverride(context.Background(), "h1"); err != nil {
		t.Fatal(err)
	}
	if err := c.ReconfigureUnbound(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(posts, ",")
	for _, want := range []string{"addHostOverride", "setHostOverride", "delHostOverride", "reconfigure"} {
		if !strings.Contains(joined, want) {
			t.Errorf("posts = %v, missing %s", posts, want)
		}
	}
}

func TestUnboundWrites_SnakeFallbackAndReconfigureErrors(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "add_host_override") || strings.Contains(r.URL.Path, "set_host_override") || strings.Contains(r.URL.Path, "del_host_override") {
			testutil.WriteBody(w, `{"result":"saved","uuid":"h-snake"}`)
			return
		}
		if strings.Contains(r.URL.Path, "reconfigure") {
			testutil.WriteBody(w, `{"status":"failed"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	id, err := c.CreateUnboundOverride(context.Background(), UnboundHostWrite{Hostname: "cam", Domain: "home.example", IP: "10.0.60.8"})
	if err != nil || id != "h-snake" {
		t.Fatalf("create snake = %q %v", id, err)
	}
	if err := c.SetUnboundOverride(context.Background(), "h1", UnboundHostWrite{Hostname: "cam", Domain: "home.example", IP: "10.0.60.8"}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteUnboundOverride(context.Background(), "h1"); err != nil {
		t.Fatal(err)
	}
	if err := c.ReconfigureUnbound(context.Background()); err == nil {
		t.Fatal("expected reconfigure status error")
	}
}

func TestUnboundHelpers(t *testing.T) {
	rows := []UnboundHostOverride{{UUID: "h1", Hostname: "nas", Domain: "home.example", IP: "10.0.40.10"}}
	if got, ok := FindUnboundOverride(rows, "h1", "", ""); !ok || got.Hostname != "nas" {
		t.Fatal("uuid match")
	}
	if got, ok := FindUnboundOverride(rows, "", "nas", "home.example"); !ok || got.UUID != "h1" {
		t.Fatal("hostname+domain match")
	}
	if _, ok := FindUnboundOverride(rows, "", "printer", "home.example"); ok {
		t.Fatal("want miss")
	}
	if !UnboundOverrideMatches(rows[0], "nas", "home.example", "10.0.40.10") {
		t.Fatal("want match")
	}
	if UnboundOverrideMatches(rows[0], "nas", "home.example", "10.0.40.11") {
		t.Fatal("want ip mismatch")
	}
	if UnboundOverrideMatches(rows[0], "printer", "home.example", "10.0.40.10") {
		t.Fatal("want hostname mismatch")
	}
}
