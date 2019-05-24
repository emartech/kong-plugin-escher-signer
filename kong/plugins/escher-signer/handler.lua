local BasePlugin = require "kong.plugins.base_plugin"
local Encrypter = require "kong.plugins.escher-signer.encrypter"
local SignatureGenerator = require "kong.plugins.escher-signer.signature_generator"
local Logger = require "logger"

local EscherSignerHandler = BasePlugin:extend()

EscherSignerHandler.PRIORITY = 500

local ISO_BASIC_DATE_FORMAT = "!%Y%m%dT%H%M%SZ"

local function get_current_service()
    return ngx.ctx.service
end

local function get_current_service_path()
    return get_current_service().path
end

local function get_upstream_path()
    return ngx.var.upstream_uri
end

local function upstream_host(service)
    if service.protocol == "http"  and service.port ~= 80 or service.protocol == "https" and service.port ~= 443 then
        return service.host .. ":" .. service.port
    end

    return service.host
end

local function get_headers_for_request_signing(conf, current_date)
    local headers = {}
    local request_headers = kong.request.get_headers()

    for _, header_name in pairs(conf.additional_headers_to_sign) do
        headers[header_name] = request_headers[header_name]
    end

    if conf.darklaunch_mode and conf.host_override then
        headers.host = conf.host_override
    else
        headers.host = upstream_host(get_current_service())
    end

    headers[conf.date_header_name] = current_date

    return headers
end

local function transform_upstream_path(uri, pattern, customer_id)
    local escaped_service_path = get_current_service_path():gsub("%-", "%%%-")
    local path_without_service_path = uri:gsub(escaped_service_path .. "/", "", 1)
    local upstream_path = pattern:gsub("{path}", path_without_service_path)

    if not customer_id then
        return upstream_path
    end

    return upstream_path:gsub("{customer_id}", customer_id)
end

local function get_request_url_with_query_parameters()
    local query_string = kong.request.get_raw_query()
    local upstream_path = get_upstream_path()

    return query_string == "" and upstream_path or ("%s?%s"):format(upstream_path, query_string)
end

local function generate_headers(conf, time)
    local current_date = os.date(ISO_BASIC_DATE_FORMAT, time)

    local request = {
        method = kong.request.get_method(),
        url = get_request_url_with_query_parameters(),
        headers = get_headers_for_request_signing(conf, current_date),
        body = kong.request.get_raw_body()
    }

    if conf.path_pattern then
        local customer_id = conf.customer_id_header and kong.request.get_header(conf.customer_id_header) or nil

        request.url = transform_upstream_path(request.url, conf.path_pattern, customer_id)
    end

    if conf.darklaunch_mode then
        Logger.getInstance(ngx):logInfo({
            darklaunch_nginx_upstream_uri = get_upstream_path(),
            darklaunch_escher_request_url = request.url,
            darklaunch_escher_body_size = string.len(request.body or ""),
            darklaunch_escher_host = request.headers.host,
            darklaunch_service_path = get_current_service_path()
        })
    end

    local decrypted_secret = Encrypter.create_from_file(conf.encryption_key_path):decrypt(conf.api_secret)

    return SignatureGenerator(conf):generate(request, conf.access_key_id, decrypted_secret, conf.credential_scope), current_date
end

local function sign_request(conf)
    local current_time = os.time()

    local auth_header, date_header = generate_headers(conf, current_time)

    if conf.darklaunch_mode then
        local auth_header_with_offset, date_header_with_offset = generate_headers(conf, current_time + 1)

        kong.service.request.set_header(conf.date_header_name .. "-Darklaunch", date_header)
        kong.service.request.set_header(conf.auth_header_name .. "-Darklaunch", auth_header)

        kong.service.request.set_header(conf.date_header_name .. "-Darklaunch-WithOffset", date_header_with_offset)
        kong.service.request.set_header(conf.auth_header_name .. "-Darklaunch-WithOffset", auth_header_with_offset)
    else
        kong.service.request.set_header(conf.date_header_name, date_header)
        kong.service.request.set_header(conf.auth_header_name, auth_header)
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
