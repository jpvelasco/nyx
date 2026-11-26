package opnsense

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

const stateDiagnostics = "/diagnostics/firewall/"

var stateHexID = regexp.MustCompile(`^[0-9a-fA-F]{1,32}$`)
var stateKillFilter = regexp.MustCompile(`^[a-zA-Z0-9 ,*_.#-]+$`)
var stateSortField = regexp.MustCompile(`^[a-z_]+$`)

type StateQuery struct {
	Search   string            `json:"searchPhrase,omitempty"`
	RuleID   string            `json:"ruleid,omitempty"`
	Sort     map[string]string `json:"sort,omitempty"`
	Page     int               `json:"current"`
	PageSize int               `json:"rowCount"`
}

type StatePage struct {
	Rows  []json.RawMessage `json:"rows"`
	Total int               `json:"total"`
	Count int               `json:"rowCount"`
	Page  int               `json:"current"`
}

type StateOperationResult struct {
	Result  string `json:"result"`
	Dropped *int   `json:"dropped_states,omitempty"`
}

// SetSort parses the optional public single-field sort syntax before dispatch.
func (q *StateQuery) SetSort(value string) error {
	q.Sort = nil
	if value == "" {
		return nil
	}
	field, order, ok := strings.Cut(value, ":")
	if !ok {
		return errors.New("--sort requires field:asc or field:desc")
	}
	q.Sort = map[string]string{field: order}
	return nil
}

func (c *Client) QueryStates(ctx context.Context, q StateQuery) (StatePage, error) {
	var page StatePage
	if q.Page < 1 || q.PageSize < 1 || q.PageSize > 9999 {
		return page, errors.New("state page requires positive page and 1–9999 rows")
	}
	if len(q.Sort) > 1 {
		return page, errors.New("state query accepts one sort field")
	}
	for field, order := range q.Sort {
		if !stateSortField.MatchString(field) || (order != "asc" && order != "desc") {
			return page, errors.New("state sort requires field:asc or field:desc")
		}
	}
	err := c.statePOST(ctx, "query_states", q, &page, true)
	if err == nil && page.Page != q.Page {
		err = errors.New("OPNsense did not return the requested state page")
	}
	return page, err
}

func (c *Client) DeleteState(ctx context.Context, id string) (StateOperationResult, error) {
	creator, state, ok := strings.Cut(id, "/")
	if !ok || !stateHexID.MatchString(creator) || !stateHexID.MatchString(state) {
		return StateOperationResult{}, errors.New("state ID must be hexadecimal creator/state")
	}
	var result StateOperationResult
	if err := c.statePOST(ctx, "del_state/"+state+"/"+creator, struct{}{}, &result, false); err != nil {
		return result, err
	}
	switch strings.TrimSpace(result.Result) {
	case "killed 1 states", "killed 1 state", "ok":
		return result, nil
	case "killed 0 states":
		return result, errors.New("state was absent or had already expired")
	default:
		return result, errors.New("OPNsense did not confirm state deletion")
	}
}

func (c *Client) KillStates(ctx context.Context, filter, ruleID string) (StateOperationResult, error) {
	filter = strings.TrimSpace(filter)
	if filter != "" && (!stateKillFilter.MatchString(filter) || strings.Trim(filter, " *.,#_-") == "" || filter == "0") {
		return StateOperationResult{}, errors.New("filter would be ignored or altered by OPNsense; use an exact state ID or a supported text filter")
	}
	if (filter == "" && ruleID == "") || (ruleID != "" && (!stateHexID.MatchString(ruleID) || ruleID == "0")) {
		return StateOperationResult{}, errors.New("state kill requires a nonempty filter or hexadecimal rule ID")
	}
	return c.runStateOperation(ctx, "kill_states", struct {
		Filter string `json:"filter,omitempty"`
		RuleID string `json:"ruleid,omitempty"`
	}{filter, ruleID})
}

func (c *Client) FlushStates(ctx context.Context) (StateOperationResult, error) {
	return c.runStateOperation(ctx, "flush_states", struct{}{})
}

func (c *Client) FlushSources(ctx context.Context) (StateOperationResult, error) {
	return c.runStateOperation(ctx, "flush_sources", struct{}{})
}

func (c *Client) runStateOperation(ctx context.Context, operation string, input any) (StateOperationResult, error) {
	var result StateOperationResult
	if err := c.statePOST(ctx, operation, input, &result, false); err != nil {
		return result, err
	}
	if strings.TrimSpace(result.Result) != "ok" {
		return result, errors.New("OPNsense did not confirm the state operation")
	}
	return result, nil
}

func (c *Client) statePOST(ctx context.Context, operation string, input, output any, replay bool) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	resp, err := c.doWithReplay(ctx, http.MethodPost, stateDiagnostics+operation, body, replay)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(output); err != nil {
		return fmt.Errorf("decoding state diagnostics response: %w", err)
	}
	return nil
}

func (c *Client) StateRuleIDs(ctx context.Context) (map[string]json.RawMessage, error) {
	var result map[string]json.RawMessage
	err := getJSON(ctx, c, stateDiagnostics+"list_rule_ids", &result)
	return result, err
}

func (c *Client) StateCapacity(ctx context.Context) (map[string]json.RawMessage, error) {
	var result map[string]json.RawMessage
	err := getJSON(ctx, c, stateDiagnostics+"pf_states", &result)
	return result, err
}
