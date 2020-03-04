local SCHEMA = {
    name = "access_key",
    primary_key = { "access_key" },
    cache_key = { "access_key" },
    fields = {
        { access_key = { type = "string", required = true, unique = true } },
        { secret = { type = "string", required = true } },
        { encryption_key_path = { type = "string", required = true} }
    }
}

return {
    access_key = SCHEMA
}
