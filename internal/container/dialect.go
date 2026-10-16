package container

import "fmt"

// NetworkAttach is one --network argument: a network name and, for sidecars
// that other containers reach by a fixed address, a static IP.
type NetworkAttach struct {
	Name string
	IP   string
}

// Dialect renders the few argv fragments where docker and podman differ. The
// rest of `run` is identical, which is what makes one Spec serve both.
type Dialect interface {
	Engine() string
	// UserArgs renders how the container process gets its uid/gid.
	UserArgs(uid, gid int) []string
	// NetworkArgs renders one network attachment.
	NetworkArgs(n NetworkAttach) []string
}

// PodmanDialect targets rootless podman.
type PodmanDialect struct{}

func (PodmanDialect) Engine() string { return "podman" }

// UserArgs maps the host user onto the image's uid/gid rather than onto its
// own numeric id. Plain keep-id maps the caller to the same number inside,
// which for any host uid other than the image's leaves the process unable to
// write the one rw mount.
func (PodmanDialect) UserArgs(uid, gid int) []string {
	return []string{fmt.Sprintf("--userns=keep-id:uid=%d,gid=%d", uid, gid)}
}

func (PodmanDialect) NetworkArgs(n NetworkAttach) []string {
	if n.IP == "" {
		return []string{"--network", n.Name}
	}
	return []string{"--network", fmt.Sprintf("%s:ip=%s", n.Name, n.IP)}
}

// DockerDialect targets docker (rootful or rootless). Docker's --userns only
// accepts "host", so the container process simply runs as the daemon's own
// uid:gid; the rw run directory is owned by that uid, so writes work.
type DockerDialect struct{}

func (DockerDialect) Engine() string { return "docker" }

func (DockerDialect) UserArgs(uid, gid int) []string {
	return []string{"--user", fmt.Sprintf("%d:%d", uid, gid)}
}

// NetworkArgs uses docker's advanced --network syntax (docker >= 25) so a
// static IP can be given per network when a container joins several.
func (DockerDialect) NetworkArgs(n NetworkAttach) []string {
	if n.IP == "" {
		return []string{"--network", n.Name}
	}
	return []string{"--network", fmt.Sprintf("name=%s,ip=%s", n.Name, n.IP)}
}

// DialectFor returns the dialect for an engine name.
func DialectFor(engine string) (Dialect, error) {
	switch engine {
	case "docker":
		return DockerDialect{}, nil
	case "podman":
		return PodmanDialect{}, nil
	}
	return nil, fmt.Errorf("unknown container engine %q (use: docker, podman)", engine)
}
