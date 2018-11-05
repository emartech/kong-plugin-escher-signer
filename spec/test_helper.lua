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

return TestHelper
