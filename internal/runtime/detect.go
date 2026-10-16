package runtime

import (
	"fmt"
	"os/exec"
)

// DetectEngine resolves "auto" to an installed engine. Podman wins when it
// is on PATH because it is rootless by default; docker is the fallback.
func DetectEngine(pref string) (string, error) {
	switch pref {
	case "docker", "podman":
		if _, err := exec.LookPath(pref); err != nil {
			return "", fmt.Errorf("runtime.engine is %q but it is not on PATH", pref)
		}
		return pref, nil
	case "", "auto":
		for _, e := range []string{"podman", "docker"} {
			if _, err := exec.LookPath(e); err == nil {
				return e, nil
			}
		}
		return "", fmt.Errorf("neither podman nor docker is on PATH")
	}
	return "", fmt.Errorf("unknown engine %q", pref)
}
