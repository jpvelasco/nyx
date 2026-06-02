package omadaprovider

import (
	"context"
	"testing"

	"github.com/jpvelasco/nyx/internal/providers"
)

func TestOmadaProviderBasics(t *testing.T) {
	p := &OmadaProvider{} // zero is fine for Name/Caps

	if p.Name() != "omada" {
		t.Errorf("Name() = %q, want omada", p.Name())
	}

	caps := p.Capabilities()
	if len(caps) != 3 {
		t.Errorf("expected 3 capabilities, got %d: %v", len(caps), caps)
	}
	has := map[string]bool{}
	for _, c := range caps {
		has[c] = true
	}
	for _, need := range []string{"info", "import", "check"} {
		if !has[need] {
			t.Errorf("missing capability %s", need)
		}
	}
}

func TestOmadaInfoWithoutHost(t *testing.T) {
	p := &OmadaProvider{}
	_, err := p.Info(context.Background(), providers.ImportOptions{})
	if err == nil {
		t.Error("expected error when no host for info")
	}
}
