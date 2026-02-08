package signer

import (
	"context"

	signerv1 "github.com/caesar-terminal/caesar/internal/gen/signer/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Handler implements the SignerServiceServer interface.
// Crypto signing logic will be wired in once KMS key fetching is ready.
type Handler struct {
	signerv1.UnimplementedSignerServiceServer
}

// SignOrder signs a Polymarket order using EIP-712 typed data.
// Currently returns Unimplemented — crypto logic comes in a later ticket.
func (h *Handler) SignOrder(_ context.Context, _ *signerv1.SignOrderRequest) (*signerv1.SignOrderResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "SignOrder not yet implemented")
}

// GetSessionStatus returns the current session key status.
// Returns inactive until session key management is wired up.
func (h *Handler) GetSessionStatus(_ context.Context, _ *signerv1.GetSessionStatusRequest) (*signerv1.GetSessionStatusResponse, error) {
	return &signerv1.GetSessionStatusResponse{
		Active:     false,
		TtlSeconds: 0,
	}, nil
}
