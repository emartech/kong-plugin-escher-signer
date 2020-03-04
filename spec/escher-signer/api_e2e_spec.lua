local helpers = require "spec.helpers"
local kong_client = require "kong_client.spec.test_helpers"
local Encrypter = require "kong.plugins.escher-signer.encrypter"

local function load_encryption_key_from_file(file_path)
    local file = assert(io.open(file_path, "r"))
    local encryption_key = file:read("*all")
    file:close()
    return encryption_key
end

describe("escher-signer admin", function()
    local send_admin_request, kong_sdk

    setup(function()
        helpers.start_kong({ plugins = "escher-signer" })
        kong_sdk = kong_client.create_kong_client()
        send_admin_request = kong_client.create_request_sender(helpers.admin_client())
    end)

    teardown(function()
        helpers.stop_kong(nil)
    end)

    describe("api-secret admin endpoint", function()
        local service, plugin_config

        local access_key = "dummy_key"
        local secret = "dummy_secret"
        local encryption_key_path = "/encryption_key.txt"

        before_each(function()
            helpers.db:truncate()
        end)

        it("should create a new record when post is called", function()
            local response = send_admin_request({
                method = "POST",
                path = "/access-key",
                body = {
                    access_key = access_key,
                    secret = secret,
                    encryption_key_path = encryption_key_path
                }
            })

            secrets, err = helpers.db.connector:query(string.format("SELECT * FROM access_key WHERE access_key = 'dummy_key'"))
            assert.is.Nil(err)
            assert.are.equal(1, #secrets)
        end)

        it("should save encoded secret into db", function()
            local response = send_admin_request({
                method = "POST",
                path = "/access-key",
                body = {
                    access_key = access_key,
                    secret = secret,
                    encryption_key_path = encryption_key_path
                }
            })

            assert.are.equal(201, response.status)

            secrets, err = helpers.db.connector:query(string.format("SELECT * FROM access_key WHERE access_key = 'dummy_key'"))

            local decrypted_secret = Encrypter.create_from_file(encryption_key_path):decrypt(secrets[1].secret)

            assert.are.equal(secret, decrypted_secret)
        end)

       
        it("should delete secret when delete is called and access key exists", function()
            local response = send_admin_request({
                method = "DELETE",
                path = "/access-key/dummy_key"
            })

            assert.are.equal(204, response.status)

            secrets, err = helpers.db.connector:query(string.format("SELECT * FROM access_key WHERE access_key = 'dummy_key'"))
            assert.are.equal(0, #secrets)
        end)

        it("should return the api secret when get is called and the access key exists", function()
            send_admin_request({
                method = "POST",
                path = "/access-key",
                body = {
                    access_key = access_key,
                    secret = secret,
                    encryption_key_path = encryption_key_path
                }
            })

            secrets, err = helpers.db.connector:query(string.format("SELECT * FROM access_key WHERE access_key = 'dummy_key'"))
            assert.is.Nil(err)
            assert.are.equal(1, #secrets)
            
            local response = send_admin_request({
                method = "GET",
                path = "/access-key/dummy_key"
            })

            assert.are.equal(200, response.status)

            access_key = response.body
            local decrypted_secret = Encrypter.create_from_file(encryption_key_path):decrypt(access_key.secret)
            
            assert.are.equal(secret, decrypted_secret)
            assert.are.equal("dummy_key", access_key.access_key)
            assert.are.equal(encryption_key_path, access_key.encryption_key_path)
        end)

        it("should respond with 404 when get is called and access key does not exist", function()            
            local response = send_admin_request({
                method = "GET",
                path = "/access-key/dummy_key"
            })

            assert.are.equal(404, response.status)
        end)
    end)
end)