local access_key_schema = kong.db.access_key.schema
local Encrypter = require "kong.plugins.escher-signer.encrypter"
local endpoints = require "kong.api.endpoints"

local function insert(db, params)
    local row, err, err_t = db.access_key:insert(params)
    if err then
        return kong.response.exit(500, {
            message = "Failed to insert resource",
            details = err_t
        })
    end
    kong.response.exit(201, row) 
end

local function encrypt_secret(params)
    local encrypter = Encrypter.create_from_file(params.encryption_key_path)
    return encrypter:encrypt(params.secret)
end

return {
    ["/access-key"] = {
        schema = access_key_schema,
        methods = {
            POST = function(self, db)
                self.params.secret = encrypt_secret(self.params)
                self.args.post.secret = encrypt_secret(self.args.post)
                return endpoints.post_collection_endpoint(access_key_schema)(self, db)
            end
        }
    },

    ["/access-key/:access_key"] = {
        schema = access_key_schema,
        methods = {
            GET = function(self, db)
                self.params.access_key = { access_key = self.params.access_key }
                local access_key, err, err_t = endpoints.select_entity(self, db, access_key_schema) 

                if err or not access_key then
                    return kong.response.exit(404, {
                        message = 'Resource does not exist'
                    })
                end

                kong.response.exit(200, access_key)
            end,

            DELETE = function(self, db)
                db.access_key:delete({ access_key_id = self.params.access_key_id })
                kong.response.exit(204)
            end
        }
    }
}
