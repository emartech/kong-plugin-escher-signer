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
            local config = {
                access_key_id = "dummy_key",
                api_secret = "dummy_secret",
                credential_scope = "dummy_credential_scope",
                encryption_key_path = "/encryption_key.txt"
            }

            local plugin = get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", config))

            local config = plugin.config

            assert.is_equal(config.vendor_key, "EMS")
            assert.is_equal(config.algo_prefix, "EMS")
            assert.is_equal(config.hash_algo, "SHA256")
            assert.is_equal(config.auth_header_name, "X-EMS-Auth")
            assert.is_equal(config.date_header_name, "X-EMS-Date")
            assert.is_equal(config.darklaunch_mode, false)
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
                local config = {
                    access_key_id = "dummy_key",
                    api_secret = "dummy_secret",
                    credential_scope = "dummy_credential_scope",
                    encryption_key_path = "i dont exist.txt"
                }
                local plugin_response = TestHelper.setup_plugin_for_service(service.id, "escher-signer", config)

                assert.res_status(400, plugin_response)
            end)
        end)

        it("should encrypt api_secret", function()
            local config = {
                access_key_id = "dummy_key",
                api_secret = "dummy_secret",
                credential_scope = "dummy_credential_scope",
                encryption_key_path = "/encryption_key.txt"
            }

            local plugin = get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", config))

            local file_path = plugin.config.encryption_key_path

            local encryption_key = TestHelper.load_encryption_key_from_file(file_path)
            local crypto = TestHelper.get_easy_crypto()

            assert.is_equal(config.api_secret, crypto:decrypt(encryption_key, plugin.config.api_secret))
        end)
    end)

    describe("Plugin", function()

        local service, route

        before_each(function()
            helpers.dao:truncate_tables()
            service = get_response_body(TestHelper.setup_service("test-service", "http://mockbin:8080/request"))
            route = get_response_body(TestHelper.setup_route_for_service(service.id, "/anything"))
        end)


        it("should set escher date header", function()
            local date_header_name = "X-Ems-Date" .. math.random(100, 999)

            local plugin_config = {
                auth_header_name = "X-Escher-Auth",
                date_header_name = date_header_name,
                access_key_id = "dummy_key",
                api_secret = "dummy_secret",
                credential_scope = "dummy_credential_scope",
                encryption_key_path = "/encryption_key.txt"
            }

            get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

            local raw_response = assert(helpers.proxy_client():send {
                method = "GET",
                path = "/anything",
                headers = {
                    ["Host"] = "example.com",
                }
            })

            local response = assert.res_status(200, raw_response)
            local body = cjson.decode(response)

            assert.is_not.Nil(body.headers[string.lower(date_header_name)])

            local date_from_header = body.headers[string.lower(date_header_name)]
            local diff = date.diff(date(date_from_header), date())

            assert.is_true(diff:spanseconds() < 5)
        end)

        it("should set escher auth header", function()
            local auth_header_name = "X-Ems-Auth" .. math.random(100, 999)

            local plugin_config = {
                vendor_key = "EMS",
                algo_prefix = "EMS",
                hash_algo = "SHA256",
                auth_header_name = auth_header_name,
                date_header_name = "X-Ems-Date",
                access_key_id = "dummy_key_v1",
                api_secret = "dummy_secret",
                credential_scope = "my/credential/scope",
                encryption_key_path = "/encryption_key.txt"
            }

            get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

            local raw_response = assert(helpers.proxy_client():send({
                method = "GET",
                path = "/anything",
            }))

            local response = assert.res_status(200, raw_response)
            local body = cjson.decode(response)
            local escher_auth_header = body.headers[string.lower(plugin_config.auth_header_name)]
            local escher_date_header = body.headers[string.lower(plugin_config.date_header_name)]

            local escher = Escher:new({
                vendorKey = "EMS",
                algoPrefix = "EMS",
                hashAlgo = "SHA256",
                credentialScope = "my/credential/scope",
                authHeaderName = auth_header_name,
                dateHeaderName = "X-Ems-Date",
                date = os.date("!%Y%m%dT%H%M%SZ")
            })

            local api_key, err = escher:authenticate(
                {
                    method = "GET",
                    url = "/anything",
                    headers = {
                        { auth_header_name, escher_auth_header },
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

        it("should clear or override existing headers", function()
            local config = {
                auth_header_name = "X-Ems-Auth",
                date_header_name = "X-Ems-Date",
                access_key_id = "dummy_key_v1",
                api_secret = "dummy_secret",
                credential_scope = "dummy_credential_scope",
                encryption_key_path = "/encryption_key.txt"
            }

            get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", config))

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

            assert.are_not.equals("some date", body.headers[string.lower(config.date_header_name)])
            assert.are_not.equals("some auth", body.headers[string.lower(config.auth_header_name)])
        end)

        context("when darklaunch_mode is enabled", function()
            it("should set date darklaunch header instead of date header", function()
                local config = {
                    auth_header_name = "X-Ems-Auth",
                    date_header_name = "X-Ems-Date",
                    access_key_id = "dummy_key_v1",
                    api_secret = "dummy_secret",
                    credential_scope = "dummy/credential/scope",
                    encryption_key_path = "/encryption_key.txt",
                    darklaunch_mode = true
                }

                get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", config))

                local raw_response = assert(helpers.proxy_client():send {
                    method = "GET",
                    path = "/anything",
                })

                local response = assert.res_status(200, raw_response)
                local body = cjson.decode(response)

                local darklaunch_date_header_name = config.date_header_name .. "-Darklaunch"

                assert.is_nil(body.headers[string.lower(config.date_header_name)])
                assert.is_not.Nil(body.headers[string.lower(darklaunch_date_header_name)])
            end)

            it("should postfix header names with '-Darklaunch'", function()
                local config = {
                    vendor_key = "EMS",
                    algo_prefix = "EMS",
                    hash_algo = "SHA256",
                    auth_header_name = "X-Ems-Auth",
                    date_header_name = "X-Ems-Date",
                    access_key_id = "dummy_key_v1",
                    api_secret = "dummy_secret",
                    credential_scope = "my/credential/scope",
                    encryption_key_path = "/encryption_key.txt",
                    darklaunch_mode = true
                }

                get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", config))

                local raw_response = assert(helpers.proxy_client():send({
                    method = "GET",
                    path = "/anything",
                }))

                local response = assert.res_status(200, raw_response)
                local body = cjson.decode(response)

                local darklaunch_auth_header_name = config.auth_header_name .. "-Darklaunch"
                assert.is_not.Nil(body.headers[string.lower(darklaunch_auth_header_name)])

                local darklaunch_date_header_name = config.date_header_name .. "-Darklaunch"
                assert.is_not.Nil(body.headers[string.lower(darklaunch_date_header_name)])
            end)

            it("should sign escher auth with date header without darklaunch postfix", function()
                local config = {
                    vendor_key = "EMS",
                    algo_prefix = "EMS",
                    hash_algo = "SHA256",
                    auth_header_name = "X-Ems-Auth",
                    date_header_name = "X-Ems-Date",
                    access_key_id = "dummy_key_v1",
                    api_secret = "dummy_secret",
                    credential_scope = "my/credential/scope",
                    encryption_key_path = "/encryption_key.txt",
                    darklaunch_mode = true
                }

                get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", config))

                local raw_response = assert(helpers.proxy_client():send({
                    method = "GET",
                    path = "/anything",
                }))

                local response = assert.res_status(200, raw_response)
                local body = cjson.decode(response)

                local darklaunch_auth_header_name = config.auth_header_name .. "-Darklaunch"
                local escher_auth_header = body.headers[string.lower(darklaunch_auth_header_name)]

                local darklaunch_date_header_name = config.date_header_name .. "-Darklaunch"
                local escher_date_header = body.headers[string.lower(darklaunch_date_header_name)]

                local escher = Escher:new({
                    vendorKey = "EMS",
                    algoPrefix = "EMS",
                    hashAlgo = "SHA256",
                    credentialScope = "my/credential/scope",
                    authHeaderName = "X-Ems-Auth",
                    dateHeaderName = "X-Ems-Date",
                    date = os.date("!%Y%m%dT%H%M%SZ")
                })

                local api_key, err = escher:authenticate(
                    {
                        method = "GET",
                        url = "/anything",
                        headers = {
                            { "X-Ems-Auth", escher_auth_header },
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
        end)

        it("should include additional signed headers in the signature", function()
            local plugin_config = {
                vendor_key = "EMS",
                algo_prefix = "EMS",
                hash_algo = "SHA256",
                auth_header_name = "X-Ems-Auth",
                date_header_name = "X-Ems-Date",
                access_key_id = "dummy_key_v1",
                api_secret = "dummy_secret",
                credential_scope = "my/credential/scope",
                encryption_key_path = "/encryption_key.txt",
                additional_headers_to_sign = { "X-Suite-CustomerId" }
            }

            get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

            local raw_response = assert(helpers.proxy_client():send({
                method = "GET",
                path = "/anything",
                headers = {
                    ["X-Suite-CustomerId"] = "112233"
                }
            }))

            local response = assert.res_status(200, raw_response)
            local body = cjson.decode(response)
            local escher_auth_header = body.headers[string.lower(plugin_config.auth_header_name)]
            local escher_date_header = body.headers[string.lower(plugin_config.date_header_name)]

            assert.not_nil(
                string.match(escher_auth_header, "SignedHeaders=[^,]*x%-suite%-customerid"),
                "Signature should have contained the X-Suite-CustomerId header"
            )

            local escher = Escher:new({
                vendorKey = "EMS",
                algoPrefix = "EMS",
                hashAlgo = "SHA256",
                credentialScope = "my/credential/scope",
                authHeaderName = "X-Ems-Auth",
                dateHeaderName = "X-Ems-Date",
                date = os.date("!%Y%m%dT%H%M%SZ")
            })

            local api_key, err = escher:authenticate(
                {
                    method = "GET",
                    url = "/anything",
                    headers = {
                        { "X-Ems-Auth", escher_auth_header },
                        { "X-Ems-Date", escher_date_header },
                        { "Host", "mockbin" },
                        { "X-Suite-CustomerId", "112233" }
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
    end)
end)
