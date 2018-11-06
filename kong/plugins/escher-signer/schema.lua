return {
    no_consumer = true,
    fields = {
        vendor_key = { type = "string", default = "EMS" },
        algo_prefix = { type = "string", default = "EMS" },
        hash_algo = { type = "string", default = "SHA256" },
        auth_header_name = { type = "string", default = "X-EMS-Auth" },
        date_header_name = { type = "string", default = "X-EMS-Date" },
        access_key_id = { type = "string", required = true },
        api_secret = { type = "string", required = true },
        credential_scope = { type = "string", required = true }
    }
}