package container

// Ownership is labels, not names. Every resource ais creates (containers,
// networks, images) carries these labels, and every lifecycle query filters
// on them. Cleanup never matches on names, so ais can never reach an
// unrelated container that happens to be called something similar.
const (
	// LabelManaged marks a resource as created by ais. Value: "true".
	LabelManaged = "io.ais.managed"
	// LabelSchema versions the label set itself. Value: SchemaVersion.
	LabelSchema = "io.ais.schema"
	// LabelRole is what the resource is for: run | proxy | backend | network | prefilter.
	LabelRole = "io.ais.role"
	// LabelTask is the task name a run container belongs to.
	LabelTask = "io.ais.task"
	// LabelRun is the run id of a run container.
	LabelRun = "io.ais.run"
	// LabelRecipe is the 16-hex recipe hash stamped on images at build time
	// and checked at run time. See internal/image.
	LabelRecipe = "io.ais.recipe"
)

// SchemaVersion is the current value of LabelSchema.
const SchemaVersion = "1"

const (
	RoleRun     = "run"
	RoleProxy   = "proxy"
	RoleBackend = "backend"
	RoleNetwork = "network"
	// RolePrefilter is the one-shot container that scores feed items.
	RolePrefilter = "prefilter"
)

// BaseLabels returns the labels common to every ais resource.
func BaseLabels(role string) map[string]string {
	return map[string]string{
		LabelManaged: "true",
		LabelSchema:  SchemaVersion,
		LabelRole:    role,
	}
}
