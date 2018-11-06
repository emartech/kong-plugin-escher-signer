local BasePlugin = require "kong.plugins.base_plugin"

local EscherSignerHandler = BasePlugin:extend()

EscherSignerHandler.PRIORITY = 2000

function EscherSignerHandler:new()
  EscherSignerHandler.super.new(self, "escher-signer")
end

function EscherSignerHandler:access(conf)
  EscherSignerHandler.super.access(self)
end

return EscherSignerHandler
