local BasePlugin = require "kong.plugins.base_plugin"

local EscherSignerHandler = BasePlugin:extend()

EscherSignerHandler.PRIORITY = 2000

function EscherSignerHandler:new()
  EscherSignerHandler.super.new(self, "escher-signer")
end

function EscherSignerHandler:access(conf)
  EscherSignerHandler.super.access(self)

  if conf.say_hello then
    ngx.log(ngx.ERR, "============ Hey World! ============")
    ngx.header["Hello-World"] = "Hey!"
  else
    ngx.log(ngx.ERR, "============ Bye World! ============")
    ngx.header["Hello-World"] = "Bye!"
  end

end

return EscherSignerHandler
