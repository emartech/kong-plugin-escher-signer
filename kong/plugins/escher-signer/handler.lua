local BasePlugin = require "kong.plugins.base_plugin"
local pp = require "pl.pretty"

local EscherSignerHandler = BasePlugin:extend()

EscherSignerHandler.PRIORITY = 2000

function EscherSignerHandler:new()
    EscherSignerHandler.super.new(self, "escher-signer")
end

function EscherSignerHandler:access(conf)
    EscherSignerHandler.super.access(self)

    ngx.req.set_header(conf.date_header_name, os.date("!%Y%m%dT%H%M%SZ"))

    --pp.dump(ngx.req.get_method())
    --
    --pp.dump(ngx.var.request_uri)
    --
    --pp.dump(ngx.req.get_headers())
    --
    --ngx.req.read_body()
    --pp.dump(ngx.req.get_body_data())
end

return EscherSignerHandler
