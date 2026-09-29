package grant

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"vectorengine.local/poc/capabilityenvelope/internal/canonical"
)

const (
	PayloadVersion = 1
	DefaultTTL     = 120 * time.Second
	MaximumTTL     = 600 * time.Second
)

type State string

const (
	Pending  State = "pending"
	Approved State = "approved"
	Denied   State = "denied"
	Consumed State = "consumed"
	Expired  State = "expired"
)

type Payload struct {
	Version          int    `json:"version"`
	GrantID          string `json:"grant_id"`
	Nonce            string `json:"nonce"`
	ToolSlug         string `json:"tool_slug"`
	ToolVersion      string `json:"tool_version"`
	SchemaSHA256     string `json:"schema_sha256"`
	PolicySHA256     string `json:"policy_sha256"`
	TaskSHA256       string `json:"task_sha256"`
	ArgumentsSHA256  string `json:"arguments_sha256"`
	IssuedAtUnixMS   int64  `json:"issued_at_unix_ms"`
	ExpiresAtUnixMS  int64  `json:"expires_at_unix_ms"`
	ApprovalRequired bool   `json:"approval_required"`
	ApprovedBy       string `json:"approved_by,omitempty"`
}

type IssueSpec struct {
	ToolSlug         string
	ToolVersion      string
	SchemaSHA256     string
	PolicySHA256     string
	TaskSHA256       string
	ArgumentsSHA256  string
	ApprovalRequired bool
	TTL              time.Duration
}

type Expected struct {
	ToolSlug        string
	ToolVersion     string
	SchemaSHA256    string
	PolicySHA256    string
	ArgumentsSHA256 string
}

type Status struct {
	GrantID          string `json:"grant_id"`
	State            State  `json:"state"`
	ToolSlug         string `json:"tool_slug"`
	ToolVersion      string `json:"tool_version"`
	ApprovalRequired bool   `json:"approval_required"`
	ApprovedBy       string `json:"approved_by,omitempty"`
	IssuedAt         string `json:"issued_at"`
	ExpiresAt        string `json:"expires_at"`
	Token            string `json:"token,omitempty"`
	DenialReason     string `json:"denial_reason,omitempty"`
}

type record struct {
	payload      Payload
	state        State
	token        string
	denialReason string
}

type Manager struct {
	mu      sync.Mutex
	secret  []byte
	now     func() time.Time
	records map[string]*record
}

func New(secret []byte, clock func() time.Time) (*Manager, error) {
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("generate grant secret: %w", err)
		}
	}
	if len(secret) < 32 {
		return nil, fmt.Errorf("grant secret must contain at least 32 bytes")
	}
	if clock == nil {
		clock = time.Now
	}
	return &Manager{
		secret:  append([]byte(nil), secret...),
		now:     clock,
		records: make(map[string]*record),
	}, nil
}

func (manager *Manager) Issue(spec IssueSpec) (Status, error) {
	return manager.IssueAndCommit(spec, nil)
}

func (manager *Manager) IssueAndCommit(spec IssueSpec, commit func(Status) error) (Status, error) {
	if spec.TTL == 0 {
		spec.TTL = DefaultTTL
	}
	if spec.TTL < time.Second || spec.TTL > MaximumTTL {
		return Status{}, fmt.Errorf("grant TTL must be between one and 600 seconds")
	}
	if spec.ToolSlug == "" || spec.ToolVersion == "" || spec.SchemaSHA256 == "" ||
		spec.PolicySHA256 == "" || spec.TaskSHA256 == "" || spec.ArgumentsSHA256 == "" {
		return Status{}, fmt.Errorf("grant issue specification is incomplete")
	}
	grantID, err := randomHex(16)
	if err != nil {
		return Status{}, err
	}
	nonce, err := randomHex(16)
	if err != nil {
		return Status{}, err
	}
	now := manager.now().UTC()
	payload := Payload{
		Version:          PayloadVersion,
		GrantID:          grantID,
		Nonce:            nonce,
		ToolSlug:         spec.ToolSlug,
		ToolVersion:      spec.ToolVersion,
		SchemaSHA256:     spec.SchemaSHA256,
		PolicySHA256:     spec.PolicySHA256,
		TaskSHA256:       spec.TaskSHA256,
		ArgumentsSHA256:  spec.ArgumentsSHA256,
		IssuedAtUnixMS:   now.UnixMilli(),
		ExpiresAtUnixMS:  now.Add(spec.TTL).UnixMilli(),
		ApprovalRequired: spec.ApprovalRequired,
	}
	state := Approved
	if spec.ApprovalRequired {
		state = Pending
	}
	entry := &record{payload: payload, state: state}
	if state == Approved {
		entry.token, err = manager.sign(payload)
		if err != nil {
			return Status{}, err
		}
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if _, collision := manager.records[grantID]; collision {
		return Status{}, fmt.Errorf("random grant ID collision")
	}
	manager.records[grantID] = entry
	status := manager.statusLocked(entry)
	if commit != nil {
		if err := commit(status); err != nil {
			delete(manager.records, grantID)
			return Status{}, err
		}
	}
	return status, nil
}

func (manager *Manager) Approve(grantID, principal string) (Status, error) {
	return manager.ApproveAndCommit(grantID, principal, nil)
}

func (manager *Manager) ApproveAndCommit(grantID, principal string, commit func(Status) error) (Status, error) {
	principal = strings.TrimSpace(principal)
	if principal == "" {
		return Status{}, fmt.Errorf("approving principal is required")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	entry, err := manager.activeLocked(grantID)
	if err != nil {
		return Status{}, err
	}
	if entry.state != Pending {
		return Status{}, fmt.Errorf("grant %s is %s, not pending", grantID, entry.state)
	}
	previous := *entry
	entry.payload.ApprovedBy = principal
	entry.token, err = manager.sign(entry.payload)
	if err != nil {
		*entry = previous
		return Status{}, err
	}
	entry.state = Approved
	status := manager.statusLocked(entry)
	if commit != nil {
		if err := commit(status); err != nil {
			*entry = previous
			return Status{}, err
		}
	}
	return status, nil
}

func (manager *Manager) Deny(grantID, reason string) (Status, error) {
	return manager.DenyAndCommit(grantID, reason, nil)
}

func (manager *Manager) DenyAndCommit(grantID, reason string, commit func(Status) error) (Status, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	entry, err := manager.activeLocked(grantID)
	if err != nil {
		return Status{}, err
	}
	if entry.state != Pending {
		return Status{}, fmt.Errorf("grant %s is %s, not pending", grantID, entry.state)
	}
	previous := *entry
	entry.state = Denied
	entry.denialReason = strings.TrimSpace(reason)
	entry.token = ""
	status := manager.statusLocked(entry)
	if commit != nil {
		if err := commit(status); err != nil {
			*entry = previous
			return Status{}, err
		}
	}
	return status, nil
}

func (manager *Manager) Inspect(grantID string) (Status, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	entry, exists := manager.records[grantID]
	if !exists {
		return Status{}, fmt.Errorf("unknown grant %s", grantID)
	}
	manager.expireLocked(entry)
	return manager.statusLocked(entry), nil
}

func (manager *Manager) List() []Status {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	result := make([]Status, 0, len(manager.records))
	for _, entry := range manager.records {
		manager.expireLocked(entry)
		status := manager.statusLocked(entry)
		status.Token = ""
		result = append(result, status)
	}
	sortStatuses(result)
	return result
}

func (manager *Manager) Consume(token string, expected Expected) (Payload, error) {
	return manager.ConsumeAndCommit(token, expected, nil)
}

func (manager *Manager) ConsumeAndCommit(token string, expected Expected, commit func(Payload) error) (Payload, error) {
	payload, err := manager.verify(token)
	if err != nil {
		return Payload{}, err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	entry, exists := manager.records[payload.GrantID]
	if !exists {
		return Payload{}, fmt.Errorf("grant is unknown")
	}
	manager.expireLocked(entry)
	if entry.state != Approved {
		return Payload{}, fmt.Errorf("grant is %s", entry.state)
	}
	if !hmac.Equal([]byte(entry.token), []byte(token)) {
		return Payload{}, fmt.Errorf("grant token is not the issued token")
	}
	if payload != entry.payload {
		return Payload{}, fmt.Errorf("grant payload differs from retained state")
	}
	if payload.ToolSlug != expected.ToolSlug {
		return Payload{}, fmt.Errorf("grant tool slug mismatch")
	}
	if payload.ToolVersion != expected.ToolVersion {
		return Payload{}, fmt.Errorf("grant tool version mismatch")
	}
	if payload.SchemaSHA256 != expected.SchemaSHA256 {
		return Payload{}, fmt.Errorf("grant schema hash mismatch")
	}
	if payload.PolicySHA256 != expected.PolicySHA256 {
		return Payload{}, fmt.Errorf("grant policy hash mismatch")
	}
	if payload.ArgumentsSHA256 != expected.ArgumentsSHA256 {
		return Payload{}, fmt.Errorf("grant arguments hash mismatch")
	}
	previous := *entry
	entry.state = Consumed
	entry.token = ""
	if commit != nil {
		if err := commit(payload); err != nil {
			*entry = previous
			return Payload{}, err
		}
	}
	return payload, nil
}

func (manager *Manager) sign(payload Payload) (string, error) {
	encoded, err := canonical.Encode(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, manager.secret)
	mac.Write(encoded)
	return base64.RawURLEncoding.EncodeToString(encoded) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (manager *Manager) verify(token string) (Payload, error) {
	encodedPart, signaturePart, exists := strings.Cut(token, ".")
	if !exists || encodedPart == "" || signaturePart == "" {
		return Payload{}, fmt.Errorf("malformed grant token")
	}
	encoded, err := base64.RawURLEncoding.DecodeString(encodedPart)
	if err != nil {
		return Payload{}, fmt.Errorf("decode grant payload: %w", err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(signaturePart)
	if err != nil {
		return Payload{}, fmt.Errorf("decode grant signature: %w", err)
	}
	mac := hmac.New(sha256.New, manager.secret)
	mac.Write(encoded)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return Payload{}, fmt.Errorf("invalid grant signature")
	}
	var payload Payload
	if err := json.Unmarshal(encoded, &payload); err != nil {
		return Payload{}, fmt.Errorf("decode grant payload: %w", err)
	}
	if payload.Version != PayloadVersion {
		return Payload{}, fmt.Errorf("unsupported grant payload version")
	}
	return payload, nil
}

func (manager *Manager) activeLocked(grantID string) (*record, error) {
	entry, exists := manager.records[grantID]
	if !exists {
		return nil, fmt.Errorf("unknown grant %s", grantID)
	}
	manager.expireLocked(entry)
	if entry.state == Expired {
		return nil, fmt.Errorf("grant %s is expired", grantID)
	}
	return entry, nil
}

func (manager *Manager) expireLocked(entry *record) {
	if entry.state == Pending || entry.state == Approved {
		if manager.now().UTC().UnixMilli() >= entry.payload.ExpiresAtUnixMS {
			entry.state = Expired
			entry.token = ""
		}
	}
}

func (manager *Manager) statusLocked(entry *record) Status {
	return Status{
		GrantID:          entry.payload.GrantID,
		State:            entry.state,
		ToolSlug:         entry.payload.ToolSlug,
		ToolVersion:      entry.payload.ToolVersion,
		ApprovalRequired: entry.payload.ApprovalRequired,
		ApprovedBy:       entry.payload.ApprovedBy,
		IssuedAt:         time.UnixMilli(entry.payload.IssuedAtUnixMS).UTC().Format(time.RFC3339Nano),
		ExpiresAt:        time.UnixMilli(entry.payload.ExpiresAtUnixMS).UTC().Format(time.RFC3339Nano),
		Token:            entry.token,
		DenialReason:     entry.denialReason,
	}
}

func randomHex(byteCount int) (string, error) {
	value := make([]byte, byteCount)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func sortStatuses(values []Status) {
	slices.SortFunc(values, func(left, right Status) int {
		if order := strings.Compare(left.IssuedAt, right.IssuedAt); order != 0 {
			return order
		}
		return strings.Compare(left.GrantID, right.GrantID)
	})
}
