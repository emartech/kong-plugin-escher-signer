local BasePlugin = require "kong.plugins.base_plugin"
local Encrypter = require "kong.plugins.escher-signer.encrypter"
local SignatureGenerator = require "kong.plugins.escher-signer.signature_generator"
local Logger = require "logger"

local EscherSignerHandler = BasePlugin:extend()

EscherSignerHandler.PRIORITY = 500

local function upstream_host(service)
    if service.protocol == "http"  and service.port ~= 80 or service.protocol == "https" and service.port ~= 443 then
        return service.host .. ":" .. service.port
    end

    return service.host
end

local function transform_upstream_path(request, pattern)
    local service_path = ngx.ctx.service.path
    local path = request.url:gsub(service_path .. "/", "", 1)

    return pattern:gsub("{path}", path)
end

local function generate_headers(conf, time)
    local decrypted_secret = Encrypter.create_from_file(conf.encryption_key_path):decrypt(conf.api_secret)

    local current_date = os.date("!%Y%m%dT%H%M%SZ", time)

    local headers = {}
    local request_headers = ngx.req.get_headers()

    for _, header_name in pairs(conf.additional_headers_to_sign) do
        headers[header_name] = request_headers[header_name]
    end

    if conf.darklaunch_mode and conf.host_override then
        headers.host = conf.host_override
    else
        headers.host = upstream_host(ngx.ctx.service)
    end

    headers[conf.date_header_name] = current_date

    ngx.req.read_body()

    local request = {
        method = ngx.req.get_method(),
        url = ngx.var.upstream_uri,
        headers = headers,
        body = ngx.req.get_body_data()
    }

    if conf.path_pattern then
        request.url = transform_upstream_path(request, conf.path_pattern)
    end

    if conf.darklaunch_mode then
        ngx.req.set_header('X-Request-Url', request.url)
        ngx.req.set_header('X-Request-Body-Size', string.len(request.body or ''))
    end

    return SignatureGenerator(conf):generate(request, conf.access_key_id, decrypted_secret , conf.credential_scope), current_date
end

local function sign_request(conf)
    local current_time = os.time()

    local auth_header, date_header = generate_headers(conf, current_time)

    if conf.darklaunch_mode then
        local auth_header_with_offset, date_header_with_offset = generate_headers(conf, current_time + 1)

        ngx.req.set_header(conf.date_header_name .. '-Darklaunch', date_header)
        ngx.req.set_header(conf.auth_header_name .. '-Darklaunch', auth_header)

        ngx.req.set_header(conf.date_header_name .. '-Darklaunch-WithOffset', date_header_with_offset)
        ngx.req.set_header(conf.auth_header_name .. '-Darklaunch-WithOffset', auth_header_with_offset)
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
