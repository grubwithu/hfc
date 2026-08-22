package modelbuilder

import (
	"fmt"
	"os/exec"
)

// execSQLViaCLI runs a command and returns an error on failure.
func execSQLViaCLI(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w\n%s", name, args, err, string(output))
	}
	return nil
}
