// Package container holds the container specification model: mounts, labels
// and the translation of a spec into an engine argv. Nothing in here talks to
// docker or podman; it only builds data for internal/runtime to execute.
package container

import (
	"fmt"
	"strings"
)

// MountType distinguishes bind mounts from named volumes. tmpfs mounts are a
// separate type (TmpfsMount) because engines take them via --tmpfs, not
// --volume, and they must never receive the SELinux relabel option.
type MountType string

const (
	MountBind   MountType = "bind"
	MountVolume MountType = "volume"
)

// Mount is one --volume argument. Every mount in ais is built as one of these
// and rendered by Render, the only path from a mount to an engine argument
// anywhere in the codebase.
//
// The reason this exists (ported from aibox): naively appending ",z" to an
// option-less mount yields "/work,z", which the engine reads as part of the
// destination path. The option list must start with ":" when there are no
// prior options and use "," only between options.
type Mount struct {
	Type    MountType
	Source  string
	Dest    string
	Options []string // e.g. "ro"; never include "z" here, Render adds it
}

// ReadOnly reports whether the mount carries the "ro" option.
func (m Mount) ReadOnly() bool {
	for _, o := range m.Options {
		if o == "ro" {
			return true
		}
	}
	return false
}

// Render returns the value of a --volume argument. selinuxRelabel appends the
// "z" relabel option, needed for mounts on SELinux-enforcing hosts; without it
// the container gets EACCES on everything mounted.
func (m Mount) Render(selinuxRelabel bool) string {
	opts := make([]string, 0, len(m.Options)+1)
	opts = append(opts, m.Options...)
	if selinuxRelabel {
		opts = append(opts, "z")
	}
	if len(opts) == 0 {
		return fmt.Sprintf("%s:%s", m.Source, m.Dest)
	}
	return fmt.Sprintf("%s:%s:%s", m.Source, m.Dest, strings.Join(opts, ","))
}

// Args returns the argv fragment for this mount.
func (m Mount) Args(selinuxRelabel bool) []string {
	return []string{"--volume", m.Render(selinuxRelabel)}
}

// TmpfsMount is one --tmpfs argument. Kept apart from Mount so a tmpfs can
// never be relabelled or given a source by accident. Options must not contain
// uid= or gid=: podman rejects them, and the mode=1777 default makes them
// unnecessary on both engines.
type TmpfsMount struct {
	Dest    string
	Options []string // e.g. "rw", "nosuid", "size=256m"
}

// Args returns the argv fragment for this tmpfs.
func (t TmpfsMount) Args() []string {
	if len(t.Options) == 0 {
		return []string{"--tmpfs", t.Dest}
	}
	return []string{"--tmpfs", fmt.Sprintf("%s:%s", t.Dest, strings.Join(t.Options, ","))}
}

// Tmpfs returns a hardened tmpfs mount of the given size: no setuid, no
// device nodes, no exec, world-writable with the sticky bit so any uid the
// container runs as can use it.
func Tmpfs(dest, size string) TmpfsMount {
	return TmpfsMount{Dest: dest, Options: []string{"rw", "nosuid", "nodev", "noexec", "mode=1777", "size=" + size}}
}
