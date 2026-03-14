package cli

// Version is the application version, set at build time via -ldflags.
// Falls back to "dev" for development builds.
var Version = "dev"

// Commit is the git commit used for the build, set at build time via -ldflags.
var Commit = ""

// Date is the build date or commit date for the build, set at build time via -ldflags.
var Date = ""

const MaintainerName = "Ahmed Nagi"
const MaintainerHandle = "nagi1"
const MaintainerX = "@nagiworks"
