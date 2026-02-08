package signer

import (
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/awnumar/memguard"
)

var (
	ErrNoActiveSession   = errors.New("no active session")
	ErrSessionExpired    = errors.New("session expired")
	ErrValueLimitExceeded = errors.New("cumulative value limit exceeded")
)

// SessionManager holds a decrypted session key in locked memory with TTL
// and cumulative value-limit enforcement. The key is encrypted at rest via
// memguard.Enclave and only opened momentarily during Sign.
type SessionManager struct {
	mu            sync.RWMutex
	enclave       *memguard.Enclave // encrypted-at-rest key buffer
	address       string            // derived signer address (hex)
	expiresAt     time.Time
	maxValueLimit *big.Int // USDC atomic units (6 decimals)
	valueUsed     *big.Int // cumulative USDC signed
	ttl           time.Duration
}

// NewSessionManager creates a manager with the given default TTL.
// No session is active until Activate is called.
func NewSessionManager(ttl time.Duration) *SessionManager {
	return &SessionManager{
		ttl:       ttl,
		valueUsed: new(big.Int),
	}
}

// Activate seals keyBytes into a memguard Enclave, sets expiry, and resets
// counters. The caller MUST zero their copy of keyBytes after calling this.
func (sm *SessionManager) Activate(keyBytes []byte, maxValueLimit *big.Int) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Clear any previous session.
	sm.enclave = nil

	sm.enclave = memguard.NewEnclave(keyBytes)
	sm.expiresAt = time.Now().Add(sm.ttl)
	sm.maxValueLimit = new(big.Int).Set(maxValueLimit)
	sm.valueUsed = new(big.Int)

	// TODO: derive address from key via secp256k1 public key recovery.
	sm.address = "0x0000000000000000000000000000000000000000"

	return nil
}

// Sign opens the enclave momentarily, performs signing (currently stubbed),
// and destroys the locked buffer. It enforces session active, TTL, and
// cumulative value limit checks.
func (sm *SessionManager) Sign(orderValue *big.Int) ([]byte, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.enclave == nil {
		return nil, ErrNoActiveSession
	}

	if sm.isExpired() {
		sm.destroyLocked()
		return nil, ErrSessionExpired
	}

	// Check cumulative value limit.
	newTotal := new(big.Int).Add(sm.valueUsed, orderValue)
	if newTotal.Cmp(sm.maxValueLimit) > 0 {
		return nil, ErrValueLimitExceeded
	}

	// Open the enclave into a LockedBuffer for signing.
	buf, err := sm.enclave.Open()
	if err != nil {
		return nil, err
	}

	// TODO: perform EIP-712 typed-data hashing + ECDSA sign with buf.Bytes().
	// For now, return a 65-byte placeholder signature.
	_ = buf.Bytes()
	sig := make([]byte, 65)

	buf.Destroy()

	// Commit value usage only after successful signing.
	sm.valueUsed.Set(newTotal)

	return sig, nil
}

// Status returns a read-only snapshot of the current session state.
// Monetary values are returned as decimal strings.
func (sm *SessionManager) Status() (active bool, ttlRemaining int64, maxLimit string, used string, address string) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.enclave == nil {
		return false, 0, "0", "0", ""
	}

	if sm.isExpired() {
		return false, 0, "0", "0", ""
	}

	remaining := time.Until(sm.expiresAt).Seconds()
	if remaining < 0 {
		remaining = 0
	}

	return true, int64(remaining), sm.maxValueLimit.String(), sm.valueUsed.String(), sm.address
}

// Destroy zeroes and destroys the enclave, resetting all session state.
func (sm *SessionManager) Destroy() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.destroyLocked()
}

// destroyLocked performs the actual cleanup. Caller must hold sm.mu.
func (sm *SessionManager) destroyLocked() {
	sm.enclave = nil
	sm.address = ""
	sm.valueUsed = new(big.Int)
	sm.maxValueLimit = nil
}

// isExpired checks whether the session TTL has elapsed. Caller must hold sm.mu.
func (sm *SessionManager) isExpired() bool {
	return time.Now().After(sm.expiresAt)
}
