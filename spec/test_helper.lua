local helpers = require "spec.helpers"

local TestHelper = {}

function TestHelper.setup_service(service_name, upstream_url)

    return assert(helpers.admin_client():send {
        method = "POST",
        path = "/services/",
        body = {
            name = service_name,
            url = upstream_url
        },
        headers = {
            ["Content-Type"] = "application/json"
        }
    })

end

function TestHelper.setup_route_for_service(service_id, path)
    return assert(helpers.admin_client():send {
        method = "POST",
        path = "/services/" .. service_id .. "/routes/",
        body = {
            paths = {path},
        },
        headers = {
            ["Content-Type"] = "application/json"
        }
    })
end

function TestHelper.setup_plugin_for_service(service_id, plugin_name, config)
    return assert(helpers.admin_client():send {
        method = "POST",
        path = "/services/" .. service_id .. "/plugins/",
        body = {
            name = plugin_name,
            config = config
        },
        headers = {
            ["Content-Type"] = "application/json"
        }
    })
end

function TestHelper.setup_consumer(customer_name)
    return assert(helpers.admin_client():send {
        method = "POST",
        path = "/consumers/",
        body = {
            username = customer_name,
        },
        headers = {
            ["Content-Type"] = "application/json"
        }
    })
end

function TestHelper.get_easy_crypto()
    local EasyCrypto = require("resty.easy-crypto")
    local ecrypto = EasyCrypto:new({ -- Initialize with default values
        saltSize = 12,
        ivSize = 16, -- for CTR mode
        iterationCount = 10000
    })
    return ecrypto
end

function TestHelper.load_encryption_key_from_file(file_path)
    local file = assert(io.open(file_path, "r"))
    local encryption_key = file:read("*all")
    file:close()
    return encryption_key
end

return TestHelper
