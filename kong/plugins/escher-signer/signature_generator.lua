local Escher = require "escher"
local Object = require "classic"

local function is_header_grouped(header_value)
    return type(header_value) == "table"
end

local function unpack_grouped_header(header_name, header_values, target_table)
    for _, header_value in ipairs(header_values) do
        table.insert(target_table, { header_name, header_value })
    end
end

local function transform_headers(headers)
    local result = {}

    for header_name, header_value in pairs(headers) do
        if is_header_grouped(header_value) then
            unpack_grouped_header(header_name, header_value, result)
        else
            table.insert(result, { header_name, header_value })
        end
    end

    return result
end

local SignatureGenerator = Object:extend()

function SignatureGenerator:new(config)
    self.config = config
end

function SignatureGenerator:generate(request, key, secret, credential_scope)
    local escher = Escher:new({
        vendorKey = self.config.vendor_key,
        algoPrefix = self.config.algo_prefix,
        hashAlgo = self.config.hash_algo,
        authHeaderName = self.config.auth_header_name,
        dateHeaderName = self.config.date_header_name,
        date = request.headers[self.config.date_header_name],
        accessKeyId = key,
        apiSecret = secret,
        credentialScope = credential_scope
    })

    local transformed_request = {
        method = request.method,
        url = request.url,
        body = request.body,
        headers = transform_headers(request.headers)
    }

    local additional_headers = {}

    for _, header_name in pairs(self.config.additional_headers_to_sign) do
        table.insert(additional_headers, header_name)
    end

    local auth_header = escher:generateHeader(transformed_request, additional_headers)

    return auth_header
end

return SignatureGenerator
