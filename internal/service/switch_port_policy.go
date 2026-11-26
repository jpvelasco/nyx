package service

import (
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/jpvelasco/nyx/internal/topology"
)

// DecodeSwitchPortPolicy requires a single JSON policy. A misspelled role or
// field fails before any controller is contacted.
func DecodeSwitchPortPolicy(text string) (topology.SwitchPortPolicy, error) {
	var policy topology.SwitchPortPolicy
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return policy, errors.New("invalid switch port policy JSON")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return policy, errors.New("switch port policy must contain one JSON object")
	}
	return policy, policy.Validate()
}
