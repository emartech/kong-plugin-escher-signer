local BasePlugin = require "kong.plugins.base_plugin"
local Encrypter = require "kong.plugins.escher-signer.encrypter"
local SignatureGenerator = require "kong.plugins.escher-signer.signature_generator"

local EscherSignerHandler = BasePlugin:extend()

EscherSignerHandler.PRIORITY = 2000

local function generate_auth_header(conf)
    local decrypted_secret = Encrypter.create_from_file(conf.encryption_key_path):decrypt(conf.api_secret)

    local headers = ngx.req.get_headers()
    headers.host = ngx.ctx.service.host

    ngx.req.read_body()

    local request = {
        method = ngx.req.get_method(),
        url = ngx.var.request_uri,
        headers = headers,
        body = ngx.req.get_body_data()
    }

    return SignatureGenerator(conf):generate(request, conf.access_key_id, decrypted_secret , conf.credential_scope)
end

function EscherSignerHandler:new()
    EscherSignerHandler.super.new(self, "escher-signer")
end

function EscherSignerHandler:access(conf)
    EscherSignerHandler.super.access(self)

    ngx.req.set_header(conf.date_header_name, os.date("!%Y%m%dT%H%M%SZ"))
    ngx.req.set_header(conf.auth_header_name, generate_auth_header(conf))
end

return EscherSignerHandler
