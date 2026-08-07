package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
)

func WaitForToken(ctx context.Context, port int) (string, error) {
	tokenChan := make(chan string)
	errChan := make(chan error)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "Missing token parameter", http.StatusBadRequest)
			errChan <- fmt.Errorf("callback received but no token was found in the URL query")
			return
		}

		docsURL := "https://docs.ennote.io/cli/overview"
		http.Redirect(w, r, docsURL, http.StatusSeeOther)

		tokenChan <- token
	})

	server := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		Handler: mux,
	}

	go func() {
		listener, err := net.Listen("tcp", server.Addr)
		if err != nil {
			errChan <- fmt.Errorf("could not start local callback server (is port %d in use?): %w", port, err)
			return
		}
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- fmt.Errorf("local server crashed: %w", err)
		}
	}()

	select {
	case token := <-tokenChan:
		_ = server.Shutdown(context.Background())
		return token, nil
	case err := <-errChan:
		_ = server.Shutdown(context.Background())
		return "", err
	case <-ctx.Done():
		_ = server.Shutdown(context.Background())
		return "", fmt.Errorf("login timed out or was cancelled by the user")
	}
}
