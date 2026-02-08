package signer

import (
	"context"
	"math/big"

	signerv1 "github.com/caesar-terminal/caesar/internal/gen/signer/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Handler implements the SignerServiceServer interface.
type Handler struct {
	signerv1.UnimplementedSignerServiceServer
	session *SessionManager
}

// NewHandler creates a Handler wired to the given SessionManager.
func NewHandler(session *SessionManager) *Handler {
	return &Handler{session: session}
}

// SignOrder signs a Polymarket order using EIP-712 typed data.
// Delegates to the SessionManager which enforces TTL and value limits.
func (h *Handler) SignOrder(_ context.Context, req *signerv1.SignOrderRequest) (*signerv1.SignOrderResponse, error) {
	if req.Order == nil {
		return nil, status.Errorf(codes.InvalidArgument, "order is required")
	}

	// Parse the maker amount as the order value for limit tracking.
	orderValue := new(big.Int)
	if _, ok := orderValue.SetString(req.Order.MakerAmount, 10); !ok {
		return nil, status.Errorf(codes.InvalidArgument, "invalid maker_amount: %s", req.Order.MakerAmount)
	}

	sig, err := h.session.Sign(orderValue)
	if err != nil {
		switch err {
		case ErrNoActiveSession:
			return nil, status.Errorf(codes.FailedPrecondition, "no active session")
		case ErrSessionExpired:
			return nil, status.Errorf(codes.FailedPrecondition, "session expired")
		case ErrValueLimitExceeded:
			return nil, status.Errorf(codes.ResourceExhausted, "cumulative value limit exceeded")
		default:
			return nil, status.Errorf(codes.Internal, "signing failed: %v", err)
		}
	}

	_, _, _, _, addr := h.session.Status()

	return &signerv1.SignOrderResponse{
		Signature:     string(sig),
		SignerAddress: addr,
	}, nil
}

// GetSessionStatus returns the current session key status.
func (h *Handler) GetSessionStatus(_ context.Context, _ *signerv1.GetSessionStatusRequest) (*signerv1.GetSessionStatusResponse, error) {
	active, ttl, maxLimit, used, addr := h.session.Status()

	return &signerv1.GetSessionStatusResponse{
		Active:         active,
		TtlSeconds:     ttl,
		MaxValueLimit:  maxLimit,
		ValueUsed:      used,
		SessionAddress: addr,
	}, nil
}
