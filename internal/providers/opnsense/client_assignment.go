package opnsense

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
)

const assignmentPath = "/interfaces/assignment/"

var ErrAssignmentUnavailable = errors.New("interface assignment API unavailable; assign and address the VLAN in the GUI")

// Assignment is the raw configuration in the stable assignment grid. Unprefixed
// fields carry values; fields beginning with % are translated display labels.
type Assignment struct {
	Identifier  string `json:"identifier"`
	Device      string `json:"if"`
	Description string `json:"descr"`
	Pending     string `json:"pending_action"`
	Enable      string `json:"enable"`
	Type4       string `json:"type4"`
	Type6       string `json:"type6"`
	Addr4       string `json:"ipaddr"`
	Addr6       string `json:"ipaddrv6"`
}

func (c *Client) Assignments(ctx context.Context) ([]Assignment, error) {
	var raw []json.RawMessage
	total, err := fetchPagedList(ctx, c, assignmentPath+"search_item", listPageSize, &raw)
	if isNotFound(err) {
		return nil, ErrAssignmentUnavailable
	}
	if err != nil {
		return nil, err
	}
	if raw == nil || total != len(raw) {
		return nil, errors.New("incomplete interface assignment inventory")
	}
	rows := make([]Assignment, len(raw))
	seen := make(map[string]bool, len(raw))
	for i, msg := range raw {
		row := &rows[i]
		if err := json.Unmarshal(msg, row); err != nil {
			return nil, err
		}
		if row.Identifier == "" || row.Device == "" || seen[row.Identifier] {
			return nil, errors.New("ambiguous interface assignment inventory")
		}
		seen[row.Identifier] = true
	}
	return rows, nil
}

func (c *Client) AssignmentsPending(ctx context.Context) (bool, error) {
	var result struct {
		Status string `json:"status"`
	}
	err := getJSON(ctx, c, assignmentPath+"pending", &result)
	if isNotFound(err) {
		return false, ErrAssignmentUnavailable
	}
	if err != nil {
		return false, err
	}
	switch result.Status {
	case "ok":
		return false, nil
	case "pending":
		return true, nil
	default:
		return false, errors.New("unknown interface assignment pending status")
	}
}

// StageAssignment adds exactly one interface; the firewall allocates its optN.
func (c *Client) StageAssignment(ctx context.Context, device, description string, address netip.Prefix) (string, error) {
	row := map[string]string{"if": device, "descr": description, "enable": "1"}
	if address.Addr().Is4() {
		row["type4"] = "staticv4"
		row["ipaddr"] = address.String()
	} else {
		row["type6"] = "staticv6"
		row["ipaddrv6"] = address.String()
	}
	body, err := json.Marshal(map[string]map[string]string{"interface": row})
	if err != nil {
		return "", err
	}
	var result natWriteResult
	if err := c.assignmentWrite(ctx, "add_item", body, &result); err != nil {
		return "", err
	}
	if result.Result != "saved" || result.UUID == "" {
		return "", errors.New("assignment add did not confirm a saved interface identifier")
	}
	return result.UUID, nil
}

func (c *Client) ActivateAssignments(ctx context.Context) error {
	var result struct {
		Status string `json:"status"`
	}
	if err := c.assignmentWrite(ctx, "reconfigure", []byte(`{}`), &result); err != nil {
		return err
	}
	if result.Status != "ok" {
		return errors.New("interface assignment reconfiguration was not confirmed")
	}
	return nil
}

func (c *Client) assignmentWrite(ctx context.Context, operation string, payload []byte, result any) error {
	resp, err := c.doWithReplay(ctx, http.MethodPost, assignmentPath+operation, payload, false)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return fmt.Errorf("decoding interface assignment %s response: %w", operation, err)
	}
	return nil
}
