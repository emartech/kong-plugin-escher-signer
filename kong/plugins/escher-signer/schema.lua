local typedefs = require "kong.db.schema.typedefs"

local function find_access_key_in_db(access_key_id)
    local result, err = kong.db.access_key:select({ access_key = access_key_id })
    if not result or err then
        return false, err or "Could not find persisted access key"
    end
    return true
end

return {
    name = "escher-signer",
    fields = {
        {
            consumer = typedefs.no_consumer
        },
        {
            config = {
                type = "record",
                fields = {
                    { access_key_id = { type = "string", required = true, custom_validator = find_access_key_in_db } },
                    { additional_headers_to_sign = { type = "array", elements = { type = "string" }, default = {} } },
                    { algo_prefix = { type = "string", default = "EMS" } },
                    { auth_header_name = { type = "string", default = "X-EMS-Auth" } },
                    { credential_scope = { type = "string", required = true } },
                    { date_header_name = { type = "string", default = "X-EMS-Date" } },
                    { darklaunch_mode = { type = "boolean", default = false } },
                    { hash_algo = { type = "string", default = "SHA256" } },
                    { host_override = { type = "string" } },
                    { path_pattern = { type = "string" } },
                    { vendor_key = { type = "string", default = "EMS" } },
                    { customer_id_header = { type = "string" } }
                }
            }
        }   
    }
}
