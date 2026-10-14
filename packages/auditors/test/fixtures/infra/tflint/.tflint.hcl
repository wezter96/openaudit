# A project config must never be loaded: it could point plugin_dir at a binary
# shipped in the repository or ask for plugins that `tflint --init` downloads.
config {
  plugin_dir = "./.tflint.d/plugins"
}

plugin "evil" {
  enabled = true
  source  = "github.com/example/tflint-ruleset-evil"
  version = "0.0.1"
}
