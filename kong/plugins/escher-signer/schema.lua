local function ensure_file_exists(file_path)
    local file = io.open(file_path, "r")

    if file == nil then
        return false, "Encryption key file could not be found."
    end

    file:close()

    return true
end

local function get_encryption_key(encryption_key_path)
    local file = io.open(encryption_key_path, "r")
    local encryption_key = file:read("*all")
    file:close()
    return encryption_key
end

local function get_easy_crypto()
    local EasyCrypto = require("resty.easy-crypto")
    return EasyCrypto:new({
        saltSize = 12,
        ivSize = 16,
        iterationCount = 10000
    })
end

local function encrypt_secret(given_value, given_config)

    local is_file_exist, error_message = ensure_file_exists(given_config.encryption_key_path)

    if not is_file_exist then
        return false, error_message
    end

    local encryption_key = get_encryption_key(given_config.encryption_key_path)
    local crypto = get_easy_crypto()

    return true, nil, { api_secret = crypto:encrypt(encryption_key, given_value)}
end

return {
    no_consumer = true,
    fields = {
        vendor_key = { type = "string", default = "EMS" },
        algo_prefix = { type = "string", default = "EMS" },
        hash_algo = { type = "string", default = "SHA256" },
        auth_header_name = { type = "string", default = "X-EMS-Auth" },
        date_header_name = { type = "string", default = "X-EMS-Date" },
        access_key_id = { type = "string", required = true },
        api_secret = { type = "string", required = true , func = encrypt_secret },
        credential_scope = { type = "string", required = true },
        encryption_key_path = { type = "string", required = true }
    }
}