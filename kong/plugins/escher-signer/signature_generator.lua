local Escher = require "escher"
local Object = require "classic"

local function transformHeaders(headersHash)
    local result = {}

    for header_name, header_value in pairs(headersHash) do
        if type(value) == "table" then
            for _, item in ipairs(header_value) do
                table.insert(result, { header_name, item })
            end
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
    local x = {
        vendorKey = self.config.vendor_key,
        algoPrefix = self.config.algo_prefix,
        hashAlgo = self.config.hash_algo,
        authHeaderName = self.config.auth_header_name,
        dateHeaderName = self.config.date_header_name,
        date = request.headers[self.config.date_header_name],
        accessKeyId = key,
        apiSecret = secret,
        credentialScope = credential_scope
    }

    local escher = Escher:new(x)

    local transformed_request = {
        method = request.method,
        url = request.url,
        body = request.body,
        headers = transformHeaders(request.headers)
    }

    local auth_header = escher:generateHeader(transformed_request, {})

    return auth_header
end

return SignatureGenerator
