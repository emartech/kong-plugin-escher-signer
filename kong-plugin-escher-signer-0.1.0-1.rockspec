package = "kong-plugin-escher-signer"
version = "0.1.0-1"
supported_platforms = {"linux", "macosx"}
source = {
  url = "git+https://github.com/emartech/kong-plugin-escher-signer.git",
  tag = "0.1.0"
}
description = {
  summary = "Escher signer plugin for Kong API gateway",
  homepage = "https://github.com/emartech/kong-plugin-escher-signer",
  license = "MIT"
}
dependencies = {
  "lua ~> 5.1",
  "classic 0.1.0-1",
  "kong-lib-logger >= 0.3.0-1"
}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.escher-signer.handler"] = "kong/plugins/escher-signer/handler.lua",
    ["kong.plugins.escher-signer.schema"] = "kong/plugins/escher-signer/schema.lua",
  }
}
