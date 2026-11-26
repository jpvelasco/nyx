package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/storepath"
)

type stagedFirmware struct {
	Host, Controller, Site, MAC, Model, Revision, Version, Digest string
}

type FirmwarePreview struct {
	Status         string `json:"status"`
	Expected       string `json:"expected_version"`
	Observed       string `json:"observed_version,omitempty"`
	WriteSupported bool   `json:"write_supported"`
}

func firmwareBytes(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, omada.MaxDeviceFirmwareBytes+1))
	if err != nil || len(b) == 0 || len(b) > omada.MaxDeviceFirmwareBytes {
		return nil, errors.New("cannot read a nonempty firmware image within the size limit")
	}
	return b, nil
}

// StageFirmware binds an operator-selected image to the authenticated target and returns an opaque local reference.
func (s *OmadaService) StageFirmware(ctx context.Context, opts OmadaOptions, dir, mac, version string, image io.Reader) (string, error) {
	parsed, err := net.ParseMAC(mac)
	version = strings.TrimSpace(version)
	if opts.Site == "" || err != nil || len(parsed) != 6 || version == "" || len(version) > 128 {
		return "", errors.New("staging requires an explicit site, managed device MAC and target version")
	}
	data, err := firmwareBytes(image)
	if err != nil {
		return "", err
	}
	return withSession(s, ctx, opts, func(c *omada.Client, siteID string) (string, error) {
		d, err := c.ManagedDevice(ctx, siteID, parsed.String())
		if err != nil {
			return "", errors.New("cannot identify selected managed device")
		}
		if c.Info().OmadaCID == "" || siteID == "" || d.Model == "" || d.FirmwareVersion == "" {
			return "", errors.New("controller, site, model and current firmware evidence are required")
		}
		manifest := stagedFirmware{Host: opts.Host, Controller: c.Info().OmadaCID, Site: siteID, MAC: parsed.String(), Model: d.Model, Revision: d.ShowModel, Version: version, Digest: fmt.Sprintf("%x", sha256.Sum256(data))}
		return saveFirmware(dir, manifest, data)
	})
}

func saveFirmware(dir string, manifest stagedFirmware, data []byte) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil { // nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission — owner traversal is required for this private directory
		return "", errors.New("cannot create private firmware staging directory")
	}
	tmp, err := os.CreateTemp(dir, ".staging-")
	if err != nil {
		return "", errors.New("cannot create private staging file")
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck
	err = json.NewEncoder(tmp).Encode(manifest)
	if err == nil {
		_, err = tmp.Write(data)
	}
	closeErr := tmp.Close()
	if err != nil || closeErr != nil {
		return "", errors.New("cannot save staged firmware")
	}
	id := rand.Text()
	if err := os.Rename(tmp.Name(), filepath.Join(dir, id)); err != nil {
		return "", errors.New("cannot publish staged firmware")
	}
	return id, nil
}

func FirmwareStageDir() string { return filepath.Join(filepath.Dir(storepath.StoreFile()), "firmware") }

var firmwareReference = regexp.MustCompile(`^[A-Z2-7]{26,64}$`)

func loadFirmware(dir, ref string) (stagedFirmware, []byte, error) {
	var m stagedFirmware
	if !firmwareReference.MatchString(ref) {
		return m, nil, errors.New("invalid firmware reference")
	}
	// Resolve the opaque reference beneath the operator’s private staging directory.
	f, err := os.OpenInRoot(dir, ref)
	if err != nil {
		return m, nil, errors.New("staged firmware unavailable")
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	header, err := reader.ReadSlice('\n')
	if err != nil || json.Unmarshal(header, &m) != nil {
		return m, nil, errors.New("invalid staged firmware manifest")
	}
	b, err := firmwareBytes(reader)
	if err != nil {
		return m, nil, err
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != m.Digest {
		return m, nil, errors.New("staged firmware digest differs")
	}
	return m, b, nil
}

// UpgradeStagedFirmware accepts only a local stage reference and the configured connection. Each hardware family needs verified support before rebooting through MCP.
func (s *OmadaService) UpgradeStagedFirmware(ctx context.Context, opts OmadaOptions, dir, ref string, confirm bool) (FirmwarePreview, error) {
	return s.upgradeStaged(ctx, opts, dir, ref, confirm, func(model, revision string) bool { return false })
}

func (s *OmadaService) upgradeStaged(ctx context.Context, opts OmadaOptions, dir, ref string, confirm bool, supported func(string, string) bool) (FirmwarePreview, error) {
	m, b, err := loadFirmware(dir, ref)
	if err != nil {
		return FirmwarePreview{}, err
	}
	if opts.Host != m.Host || opts.Site == "" {
		return FirmwarePreview{}, errors.New("select the configured connection and site used for staging")
	}
	return withSession(s, ctx, opts, func(c *omada.Client, siteID string) (FirmwarePreview, error) {
		if c.Info().OmadaCID != m.Controller || siteID != m.Site {
			return FirmwarePreview{}, errors.New("configured controller or site differs from staged target")
		}
		d, err := c.ManagedDevice(ctx, siteID, m.MAC)
		if err != nil || d.Model != m.Model || d.ShowModel != m.Revision {
			return FirmwarePreview{}, errors.New("managed device identity differs from staged target")
		}
		out := FirmwarePreview{Expected: m.Version, Observed: d.FirmwareVersion, WriteSupported: supported(d.Model, d.ShowModel)}
		if confirm && !out.WriteSupported {
			out.Status = "hardware_support_unverified"
			return out, nil
		}
		r, err := c.UpgradeDevice(ctx, siteID, m.MAC, m.Version, bytes.NewReader(b), confirm)
		out.Status = r.Status
		out.Observed = r.ObservedFirmware
		if err != nil {
			return out, errors.New("firmware operation was not verified; inspect the selected device before retrying")
		}
		return out, nil
	})
}
