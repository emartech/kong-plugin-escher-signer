local helpers = require "spec.helpers"
local cjson = require "cjson"
local TestHelper = require "spec.test_helper"

local function get_response_body(response)
    local body = assert.res_status(201, response)
    return cjson.decode(body)
end

local function setup_test_env()
    helpers.dao:truncate_tables()

    local service = get_response_body(TestHelper.setup_service("test-service", "http://mockbin:8080/request"))
    local route = get_response_body(TestHelper.setup_route_for_service(service.id, "/anything"))
    local plugin = get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer"))
    local consumer = get_response_body(TestHelper.setup_consumer("TestUser"))
    return service, route, plugin, consumer
end

describe("Plugin: escher-signer (access)", function()

    setup(function()
        helpers.start_kong({ custom_plugins = "escher-signer" })
    end)

    teardown(function()
        helpers.stop_kong(nil)
    end)

    describe("Escher Signer", function()
        local service

        before_each(function()
            helpers.dao:truncate_tables()
            service = get_response_body(TestHelper.setup_service("test-service", "http://mockbin:8080/request"))
        end)

        it("should set default config items on empty config", function()
            local mock_config = {
                access_key_id = "dummy_key",
                api_secret = "dummy_secret",
                credential_scope = "dummy_credential_scope",
                encryption_key_path = "/encryption_key.txt"
            }

            local plugin = get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", mock_config))

            local config = plugin.config

            assert.is_equal(config.vendor_key, "EMS")
            assert.is_equal(config.algo_prefix, "EMS")
            assert.is_equal(config.hash_algo, "SHA256")
            assert.is_equal(config.auth_header_name, "X-EMS-Auth")
            assert.is_equal(config.date_header_name, "X-EMS-Date")
        end)

        it("should require access_key_id, api_secret, credantial_scope and encryption_key_path", function()
            local plugin_response = TestHelper.setup_plugin_for_service(service.id, "escher-signer", {})

            local body = assert.res_status(400, plugin_response)
            local plugin = cjson.decode(body)

            assert.is_equal(plugin["config.access_key_id"], "access_key_id is required")
            assert.is_equal(plugin["config.api_secret"], "api_secret is required")
            assert.is_equal(plugin["config.credential_scope"], "credential_scope is required")
            assert.is_equal(plugin["config.encryption_key_path"], "encryption_key_path is required")
        end)

        context("when encryption file does not exists", function()
            it("should respond 400", function()
                local mock_config = {
                    access_key_id = "dummy_key",
                    api_secret = "dummy_secret",
                    credential_scope = "dummy_credential_scope",
                    encryption_key_path = "i dont exist.txt"
                }
                local plugin_response = TestHelper.setup_plugin_for_service(service.id, "escher-signer", mock_config)

                assert.res_status(400, plugin_response)
            end)
        end)

        it("should encrypt api_secret", function()
            local mock_config = {
                access_key_id = "dummy_key",
                api_secret = "dummy_secret",
                credential_scope = "dummy_credential_scope",
                encryption_key_path = "/encryption_key.txt"
            }

            local plugin = get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", mock_config))

            local file_path = plugin.config.encryption_key_path

            local encryption_key = TestHelper.load_encryption_key_from_file(file_path)
            local crypto = TestHelper.get_easy_crypto()

            assert.is_equal(mock_config.api_secret, crypto:decrypt(encryption_key, plugin.config.api_secret))
        end)
    end)

end)
