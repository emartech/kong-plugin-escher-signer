local Encrypter = require "kong.plugins.escher-signer.encrypter"

local function ensure_file_exists(file_path)
    local file = io.open(file_path, "r")

    if file == nil then
        return false, "Encryption key file could not be found."
    end

    file:close()

    return true
end

local function encrypt_secret(given_value, given_config)

    local is_file_exist, error_message = ensure_file_exists(given_config.encryption_key_path)

    if not is_file_exist then
        return false, error_message
    end

    local encrypter = Encrypter.create_from_file(given_config.encryption_key_path)

    return true, nil, { api_secret = encrypter:encrypt(given_value)}
end

return {
    no_consumer = true,
    fields = {
        access_key_id = { type = "string", required = true },
        additional_headers_to_sign = { type = "array", default = {} },
        algo_prefix = { type = "string", default = "EMS" },
        api_secret = { type = "string", required = true , func = encrypt_secret },
        auth_header_name = { type = "string", default = "X-EMS-Auth" },
        credential_scope = { type = "string", required = true },
        date_header_name = { type = "string", default = "X-EMS-Date" },
        darklaunch_mode = { type = "boolean", default = false },
        encryption_key_path = { type = "string", required = true },
        hash_algo = { type = "string", default = "SHA256" },
        host_override = { type = "string" },
        vendor_key = { type = "string", default = "EMS" }
    }
}
