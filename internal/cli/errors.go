package cli

import (
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func handleGRPCError(err error) error {
	if err == nil {
		return nil
	}

	if st, ok := status.FromError(err); ok {
		return formatStatus(st)
	}

	return err
}

func formatStatus(st *status.Status) error {
	if st.Code() == codes.Unauthenticated {
		return fmt.Errorf("unauthorized: no active session found. Please set the ENNOTE_TOKEN environment variable or run 'ennote auth login'")
	}
	return errors.New(st.Message())
}
