local BasePlugin = require "kong.plugins.base_plugin"
local Encrypter = require "kong.plugins.escher-signer.encrypter"
local SignatureGenerator = require "kong.plugins.escher-signer.signature_generator"
local Logger = require "logger"

local EscherSignerHandler = BasePlugin:extend()

EscherSignerHandler.PRIORITY = 2000

local function generate_headers(conf)
    local decrypted_secret = Encrypter.create_from_file(conf.encryption_key_path):decrypt(conf.api_secret)

    local current_date = os.date("!%Y%m%dT%H%M%SZ")

    local headers = ngx.req.get_headers()

    headers.host = ngx.ctx.service.host
    headers[conf.date_header_name] = current_date

    ngx.req.read_body()

    local request = {
        method = ngx.req.get_method(),
        url = ngx.var.request_uri,
        headers = headers,
        body = ngx.req.get_body_data()
    }

    return SignatureGenerator(conf):generate(request, conf.access_key_id, decrypted_secret , conf.credential_scope), current_date
end

local function sign_request(conf)
    local auth_header, date_header = generate_headers(conf)

    if conf.darklaunch_mode then
        ngx.req.set_header(conf.date_header_name .. '-Darklaunch', date_header)
        ngx.req.set_header(conf.auth_header_name .. '-Darklaunch', auth_header)
    else
        ngx.req.set_header(conf.date_header_name, date_header)
        ngx.req.set_header(conf.auth_header_name, auth_header)
    end
end

function EscherSignerHandler:new()
    EscherSignerHandler.super.new(self, "escher-signer")
end

function EscherSignerHandler:access(conf)
    EscherSignerHandler.super.access(self)

    local success, error = pcall(sign_request, conf)

    if not success then
        Logger.getInstance(ngx):logError(error)
    end
end

return EscherSignerHandler
