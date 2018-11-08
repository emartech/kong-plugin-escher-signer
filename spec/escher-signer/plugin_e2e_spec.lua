local helpers = require "spec.helpers"
local cjson = require "cjson"
local Escher = require "escher"
local date = require "date"
local TestHelper = require "spec.test_helper"

local function get_response_body(response)
    local body = assert.res_status(201, response)
    return cjson.decode(body)
end

local function setup_test_env()
    helpers.dao:truncate_tables()

    local service = get_response_body(TestHelper.setup_service("test-service", "http://mockbin:8080/request"))
    local route = get_response_body(TestHelper.setup_route_for_service(service.id, "/anything"))
    local plugin = get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer",{}))
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

    describe("Plugin", function()

        local service, route

        before_each(function()
            helpers.dao:truncate_tables()
            service = get_response_body(TestHelper.setup_service("test-service", "http://mockbin:8080/request"))
            route = get_response_body(TestHelper.setup_route_for_service(service.id, "/anything"))
        end)

        local test_cases_for_date_header = {
            "X-Escher-Date", "Some-Other-Header"
        }

        for test_case = 1, #test_cases_for_date_header do

            it("should set escher date header properly with " .. test_cases_for_date_header[test_case], function()
                local mock_config = {
                    auth_header_name = "X-Escher-Auth",
                    date_header_name = test_cases_for_date_header[test_case],
                    access_key_id = "dummy_key",
                    api_secret = "dummy_secret",
                    credential_scope = "dummy_credential_scope",
                    encryption_key_path = "/encryption_key.txt"
                }

                get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", mock_config))

                local raw_response = assert(helpers.proxy_client():send {
                    method = "GET",
                    path = "/anything",
                    headers = {
                        ["Host"] = "example.com",
                    }
                })

                local response = assert.res_status(200, raw_response)
                local body = cjson.decode(response)

                assert.is_not.Nil(body.headers[string.lower(mock_config.date_header_name)])

                local date_from_header = body.headers[string.lower(mock_config.date_header_name)]
                local diff = date.diff(date(date_from_header), date())

                assert.is_true(diff:spanseconds() < 5)
            end)
        end

        local test_cases_for_auth_header = {
            "X-Escher-Auth", "Some-Different-Header"
        }

        for test_case = 1, #test_cases_for_auth_header do

            it("should set escher auth header properly with " .. test_cases_for_auth_header[test_case], function()
                local mock_config = {
                    vendor_key = "EMS",
                    algo_prefix = "EMS",
                    hash_algo = "SHA256",
                    auth_header_name = test_cases_for_auth_header[test_case],
                    date_header_name = "X-Ems-Date",
                    access_key_id = "dummy_key_v1",
                    api_secret = "dummy_secret",
                    credential_scope = "my/credential/scope",
                    encryption_key_path = "/encryption_key.txt"
                }

                get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", mock_config))

                local raw_response = assert(helpers.proxy_client():send({
                    method = "GET",
                    path = "/anything",
                }))

                local response = assert.res_status(200, raw_response)
                local body = cjson.decode(response)
                local escher_auth_header = body.headers[string.lower(mock_config.auth_header_name)]
                local escher_date_header = body.headers[string.lower(mock_config.date_header_name)]

                local escher = Escher:new({
                    vendorKey = "EMS",
                    algoPrefix = "EMS",
                    hashAlgo = "SHA256",
                    credentialScope = "my/credential/scope",
                    authHeaderName = test_cases_for_auth_header[test_case],
                    dateHeaderName = "X-Ems-Date",
                    date = os.date("!%Y%m%dT%H%M%SZ")
                })

                local api_key, err = escher:authenticate(
                    {
                        method = "GET",
                        url = "/anything",
                        headers = {
                            { test_cases_for_auth_header[test_case], escher_auth_header },
                            { "X-Ems-Date", escher_date_header },
                            { "Host", "mockbin" }
                        },
                    }, function(key)
                        if key == "dummy_key_v1" then
                            return "dummy_secret"
                        end

                        error("Escher key not found")
                    end
                )

                assert.are.equal("dummy_key_v1", api_key, err)
            end)
        end

        it("should clear or override existing headers", function()
            local mock_config = {
                auth_header_name = "X-Ems-Auth",
                date_header_name = "X-Ems-Date",
                access_key_id = "dummy_key_v1",
                api_secret = "dummy_secret",
                credential_scope = "dummy_credential_scope",
                encryption_key_path = "/encryption_key.txt"
            }

            get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", mock_config))

            local raw_response = assert(helpers.proxy_client():send {
                method = "GET",
                path = "/anything",
                headers = {
                    ["Host"] = "example.com",
                    ["X-Ems-Date"] = "some date",
                    ["X-Ems-Auth"] = "some auth"
                }
            })

            local response = assert.res_status(200, raw_response)
            local body = cjson.decode(response)

            require "pl.pretty".dump(body.headers)

            assert.are_not.equals("some date", body.headers[string.lower(mock_config.auth_header_name)])
            assert.are_not.equals("some auth", body.headers[string.lower(mock_config.date_header_name)])
        end)
    end)
end)
