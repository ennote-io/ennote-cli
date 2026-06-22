package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

func executeWithEnv(args []string, envVars map[string]string) error {
	cmdName := args[0]

	resolvedPath, err := exec.LookPath(cmdName)
	if err != nil {
		return fmt.Errorf("executable %q not found in system $PATH: %w", cmdName, err)
	}

	var cmdArgs []string
	if len(args) > 1 {
		cmdArgs = args[1:]
	}

	cmd := exec.Command(resolvedPath, cmdArgs...)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	env := os.Environ()
	for k, v := range envVars {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env

	if err := cmd.Run(); err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			return fmt.Errorf("process exited with status %d", exitErr.ExitCode())
		}
		return fmt.Errorf("failed to start process %q: %w", cmdName, err)
	}

	return nil
}
