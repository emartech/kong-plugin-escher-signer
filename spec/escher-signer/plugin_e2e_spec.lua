local helpers = require "spec.helpers"
local cjson = require "cjson"
local Escher = require "escher"
local date = require "date"
local TestHelper = require "spec.test_helper"

local function get_response_body(response)
    local body = assert.res_status(201, response)
    return cjson.decode(body)
end

describe("Plugin: escher-signer", function()

    setup(function()
        helpers.start_kong({ plugins = "escher-signer" })
    end)

    teardown(function()
        helpers.stop_kong(nil)
    end)

    describe("config", function()
        local service, plugin_config

        before_each(function()
            helpers.db:truncate()

            service = get_response_body(TestHelper.setup_service("test-service", "http://mockbin:8080/request"))

            plugin_config = {
                access_key_id = "dummy_key",
                api_secret = "dummy_secret",
                credential_scope = "dummy_credential_scope",
                encryption_key_path = "/encryption_key.txt"
            }
        end)

        it("should set default config items on empty config", function()
            local plugin = get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

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

        it("should allow host_override, path_pattern", function()
            plugin_config.host_override = "custom-host"
            plugin_config.path_pattern = "/example/{customer_id}/{path}"

            local plugin = get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

            local config = plugin.config

            assert.is_equal(config.host_override, "custom-host")
            assert.is_equal(config.path_pattern, "/example/{customer_id}/{path}")
        end)

        context("when encryption file does not exists", function()
            it("should respond 400", function()
                plugin_config.encryption_key_path = "i dont exist.txt"

                local plugin_response = TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config)

                assert.res_status(400, plugin_response)
            end)
        end)

        it("should encrypt api_secret", function()
            local plugin = get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

            local file_path = plugin.config.encryption_key_path

            local encryption_key = TestHelper.load_encryption_key_from_file(file_path)
            local crypto = TestHelper.get_easy_crypto()

            assert.is_equal(plugin_config.api_secret, crypto:decrypt(encryption_key, plugin.config.api_secret))
        end)
    end)

    describe(".access", function()
        local service, route, plugin_config

        local function escher_key_db(key)
            if key == plugin_config.access_key_id then
                return plugin_config.api_secret
            end

            error("Escher key not found")
        end

        local function escher_authenticate(request)
            local escher = Escher:new({
                vendorKey = plugin_config.vendor_key or "EMS",
                algoPrefix = plugin_config.algo_prefix or "EMS",
                hashAlgo = plugin_config.hash_algo or "SHA256",
                credentialScope = plugin_config.credential_scope,
                authHeaderName = plugin_config.auth_header_name,
                dateHeaderName = plugin_config.date_header_name,
                date = os.date("!%Y%m%dT%H%M%SZ")
            })

            local api_key, err = escher:authenticate({
                method = request.method,
                url = request.url,
                headers = request.headers
            }, escher_key_db)

            return api_key, err
        end

        before_each(function()
            helpers.db:truncate()

            service = get_response_body(TestHelper.setup_service("test-service", "http://mockbin:8080/request"))

            route = get_response_body(TestHelper.setup_route_for_service(service.id, "/anything"))

            plugin_config = {
                auth_header_name = "X-Ems-Auth" .. math.random(100, 999),
                date_header_name = "X-Ems-Date" .. math.random(100, 999),
                access_key_id = "dummy_key",
                api_secret = "dummy_secret",
                credential_scope = "dummy/credential/scope",
                encryption_key_path = "/encryption_key.txt"
            }
        end)

        it("should set escher date header", function()
            get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

            local raw_response = assert(helpers.proxy_client():send({
                method = "GET",
                path = "/anything/something"
            }))

            local response = assert.res_status(200, raw_response)
            local body = cjson.decode(response)

            local escher_date_header = body.headers[string.lower(plugin_config.date_header_name)]

            assert.is_not.Nil(escher_date_header)

            local diff = date.diff(date(escher_date_header), date())

            assert.is_true(diff:spanseconds() < 5)
        end)

        it("should set escher auth header", function()
            get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

            local raw_response = assert(helpers.proxy_client():send({
                method = "GET",
                path = "/anything/something"
            }))

            local response = assert.res_status(200, raw_response)
            local body = cjson.decode(response)

            local auth_header_name = plugin_config.auth_header_name
            local date_header_name = plugin_config.date_header_name

            local escher_auth_header = body.headers[string.lower(auth_header_name)]
            local escher_date_header = body.headers[string.lower(date_header_name)]

            local api_key, err = escher_authenticate({
                method = "GET",
                url = "/request/something",
                headers = {
                    { auth_header_name, escher_auth_header },
                    { date_header_name, escher_date_header },
                    { "Host", "mockbin:8080" }
                }
            })

            assert("dummy_key" == api_key, err)
        end)

        it("should sign host header w/o port when using scheme default", function()
            local service = get_response_body(TestHelper.setup_service("test-service-80", "http://mockbin80:80/request"))

            get_response_body(TestHelper.setup_route_for_service(service.id, "/anything-80"))

            plugin_config.access_key_id = "dummy_key_v1"

            get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

            local raw_response = assert(helpers.proxy_client():send({
                method = "GET",
                path = "/anything-80/something",
            }))

            local response = assert.res_status(200, raw_response)
            local body = cjson.decode(response)

            local auth_header_name = plugin_config.auth_header_name
            local date_header_name = plugin_config.date_header_name

            local escher_auth_header = body.headers[string.lower(auth_header_name)]
            local escher_date_header = body.headers[string.lower(date_header_name)]

            local api_key, err = escher_authenticate({
                method = "GET",
                url = "/request/something",
                headers = {
                    { auth_header_name, escher_auth_header },
                    { date_header_name, escher_date_header },
                    { "Host", "mockbin80" }
                }
            })

            assert("dummy_key_v1" == api_key, err)
        end)

        it("should sign query params", function()
            get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

            local raw_response = assert(helpers.proxy_client():send({
                method = "GET",
                path = "/anything/something?valami=akarmi&barmi=semmi"
            }))

            local response = assert.res_status(200, raw_response)
            local body = cjson.decode(response)

            local auth_header_name = plugin_config.auth_header_name
            local date_header_name = plugin_config.date_header_name

            local escher_auth_header = body.headers[string.lower(auth_header_name)]
            local escher_date_header = body.headers[string.lower(date_header_name)]

            local api_key, err = escher_authenticate({
                method = "GET",
                url = "/request/something?valami=akarmi&barmi=semmi",
                headers = {
                    { auth_header_name, escher_auth_header },
                    { date_header_name, escher_date_header },
                    { "Host", "mockbin:8080" }
                }
            })

            assert("dummy_key" == api_key, err)
        end)

        it("should sign query params", function()
            get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

            local raw_response = assert(helpers.proxy_client():send({
                method = "GET",
                path = "/anything/something?"
            }))

            local response = assert.res_status(200, raw_response)
            local body = cjson.decode(response)

            local auth_header_name = plugin_config.auth_header_name
            local date_header_name = plugin_config.date_header_name

            local escher_auth_header = body.headers[string.lower(auth_header_name)]
            local escher_date_header = body.headers[string.lower(date_header_name)]

            local api_key, err = escher_authenticate({
                method = "GET",
                url = "/request/something",
                headers = {
                    { auth_header_name, escher_auth_header },
                    { date_header_name, escher_date_header },
                    { "Host", "mockbin:8080" }
                }
            })

            assert("dummy_key" == api_key, err)
        end)

        it("should clear or override existing headers", function()
            get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

            local raw_response = assert(helpers.proxy_client():send({
                method = "GET",
                path = "/anything/something",
                headers = {
                    ["Host"] = "example.com",
                    ["X-Ems-Date"] = "some date",
                    ["X-Ems-Auth"] = "some auth"
                }
            }))

            local response = assert.res_status(200, raw_response)
            local body = cjson.decode(response)

            assert.are_not.equals("some date", body.headers[string.lower(plugin_config.date_header_name)])
            assert.are_not.equals("some auth", body.headers[string.lower(plugin_config.auth_header_name)])
        end)

        context("when auth headers already exist on the request", function()
            it("should sign request with correct headers", function()
                get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

                local raw_response = assert(helpers.proxy_client():send({
                    method = "GET",
                    path = "/anything/something",
                    headers = {
                        [plugin_config.date_header_name] = 'existing header value'
                    }
                }))

                local response = assert.res_status(200, raw_response)
                local body = cjson.decode(response)

                local auth_header_name = plugin_config.auth_header_name
                local date_header_name = plugin_config.date_header_name

                local escher_auth_header = body.headers[string.lower(auth_header_name)]
                local escher_date_header = body.headers[string.lower(date_header_name)]

                local api_key, err = escher_authenticate({
                    method = "GET",
                    url = "/request/something",
                    headers = {
                        { auth_header_name, escher_auth_header },
                        { date_header_name, escher_date_header },
                        { "Host", "mockbin:8080" }
                    }
                })

                assert("dummy_key" == api_key, err)
            end)
        end)

        context("when darklaunch_mode is enabled", function()
            before_each(function()
                plugin_config.darklaunch_mode = true
            end)

            it("should set date darklaunch header instead of date header", function()
                get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

                local raw_response = assert(helpers.proxy_client():send({
                    method = "GET",
                    path = "/anything/something"
                }))

                local response = assert.res_status(200, raw_response)
                local body = cjson.decode(response)

                local darklaunch_date_header_name = plugin_config.date_header_name .. "-Darklaunch"

                assert.is_nil(body.headers[string.lower(plugin_config.date_header_name)])
                assert.is_not.Nil(body.headers[string.lower(darklaunch_date_header_name)])
            end)

            it("should postfix header names with '-Darklaunch'", function()
                get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

                local raw_response = assert(helpers.proxy_client():send({
                    method = "GET",
                    path = "/anything/something"
                }))

                local response = assert.res_status(200, raw_response)
                local body = cjson.decode(response)

                local darklaunch_auth_header_name = plugin_config.auth_header_name .. "-Darklaunch"
                local darklaunch_date_header_name = plugin_config.date_header_name .. "-Darklaunch"

                assert.is_not.Nil(body.headers[string.lower(darklaunch_auth_header_name)])
                assert.is_not.Nil(body.headers[string.lower(darklaunch_date_header_name)])
            end)

            it("should sign escher auth with date header without darklaunch postfix", function()
                plugin_config.access_key_id = "dummy_key_v1"

                get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

                local raw_response = assert(helpers.proxy_client():send({
                    method = "GET",
                    path = "/anything/something"
                }))

                local response = assert.res_status(200, raw_response)
                local body = cjson.decode(response)

                local darklaunch_auth_header_name = plugin_config.auth_header_name .. "-Darklaunch"
                local darklaunch_date_header_name = plugin_config.date_header_name .. "-Darklaunch"

                local escher_auth_header = body.headers[string.lower(darklaunch_auth_header_name)]
                local escher_date_header = body.headers[string.lower(darklaunch_date_header_name)]

                local api_key, err = escher_authenticate({
                    method = "GET",
                    url = "/request/something",
                    headers = {
                        { plugin_config.auth_header_name, escher_auth_header },
                        { plugin_config.date_header_name, escher_date_header },
                        { "Host", "mockbin:8080" }
                    }
                })

                assert("dummy_key_v1" == api_key, err)
            end)

            it("should set another date header with one second offset", function()
                get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

                local raw_response = assert(helpers.proxy_client():send({
                    method = "GET",
                    path = "/anything/something"
                }))

                local response = assert.res_status(200, raw_response)
                local body = cjson.decode(response)

                local darklaunch_date_header_name = plugin_config.date_header_name .. "-Darklaunch"
                local darklaunch_date_header_name_with_offset = darklaunch_date_header_name .. "-WithOffset"

                assert.is_not.Nil(body.headers[string.lower(darklaunch_date_header_name_with_offset)])

                local time_in_darklaunch_header = body.headers[string.lower(darklaunch_date_header_name)]
                local time_with_offset = body.headers[string.lower(darklaunch_date_header_name_with_offset)]
                local diff = date.diff(date(time_with_offset), date(time_in_darklaunch_header))

                assert.are.equal(1, diff:spanseconds())
            end)

            it("should use host_override instead of actual host header", function()
                plugin_config.host_override = "custom-host"

                get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

                local raw_response = assert(helpers.proxy_client():send({
                    method = "GET",
                    path = "/anything/something"
                }))

                local response = assert.res_status(200, raw_response)
                local body = cjson.decode(response)

                local darklaunch_auth_header_name = plugin_config.auth_header_name .. "-Darklaunch"
                local darklaunch_date_header_name = plugin_config.date_header_name .. "-Darklaunch"

                local escher_auth_header = body.headers[string.lower(darklaunch_auth_header_name)]
                local escher_date_header = body.headers[string.lower(darklaunch_date_header_name)]

                local api_key, err = escher_authenticate({
                    method = "GET",
                    url = "/request/something",
                    headers = {
                        { plugin_config.auth_header_name, escher_auth_header },
                        { plugin_config.date_header_name, escher_date_header },
                        { "Host", "custom-host" }
                    }
                })

                assert("dummy_key" == api_key, err)
            end)

            it("should sign escher auth with date header without darklaunch postfix", function()
                plugin_config.access_key_id = "dummy_key_v1"

                get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

                local raw_response = assert(helpers.proxy_client():send({
                    method = "GET",
                    path = "/anything/something",
                }))

                local response = assert.res_status(200, raw_response)
                local body = cjson.decode(response)

                local darklaunch_auth_header_name_with_offset = plugin_config.auth_header_name .. "-Darklaunch-WithOffset"
                local darklaunch_date_header_name_with_offset = plugin_config.date_header_name .. "-Darklaunch-WithOffset"

                local escher_auth_header = body.headers[string.lower(darklaunch_auth_header_name_with_offset)]
                local escher_date_header = body.headers[string.lower(darklaunch_date_header_name_with_offset)]

                local api_key, err = escher_authenticate({
                    method = "GET",
                    url = "/request/something",
                    headers = {
                        { plugin_config.auth_header_name, escher_auth_header },
                        { plugin_config.date_header_name, escher_date_header },
                        { "Host", "mockbin:8080" }
                    }
                })

                assert("dummy_key_v1" == api_key, err)
            end)
        end)

        it("should include additional signed headers in the signature", function()
            plugin_config.additional_headers_to_sign = { "X-Suite-CustomerId" }

            get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

            local raw_response = assert(helpers.proxy_client():send({
                method = "GET",
                path = "/anything/something",
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

            local api_key, err = escher_authenticate({
                method = "GET",
                url = "/request/something",
                headers = {
                    { plugin_config.auth_header_name, escher_auth_header },
                    { plugin_config.date_header_name, escher_date_header },
                    { "Host", "mockbin:8080" },
                    { "X-Suite-CustomerId", "112233" }
                }
            })

            assert("dummy_key" == api_key, err)
        end)

        context("when path_pattern is used", function()
            it("should use path to sign request", function()
                -- plugin_config.path_pattern = "/api/{path}"

                -- get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

                -- local raw_response = assert(helpers.proxy_client():send({
                --     method = "GET",
                --     path = "/anything/something"
                -- }))

                local service = get_response_body(TestHelper.setup_service("test-service-with-dash", "http://mockbin:8080/request/any-thing"))

                get_response_body(TestHelper.setup_route_for_service(service.id, "/any-thing"))

                plugin_config.access_key_id = "dummy_key_v1"
                plugin_config.path_pattern = "/api/{path}"

                get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

                local raw_response = assert(helpers.proxy_client():send({
                    method = "GET",
                    path = "/any-thing/something",
                }))

                local response = assert.res_status(200, raw_response)
                local body = cjson.decode(response)

                local auth_header_name = plugin_config.auth_header_name
                local date_header_name = plugin_config.date_header_name

                local escher_auth_header = body.headers[string.lower(auth_header_name)]
                local escher_date_header = body.headers[string.lower(date_header_name)]

                local api_key, err = escher_authenticate({
                    method = "GET",
                    url = "/api/something",
                    headers = {
                        { auth_header_name, escher_auth_header },
                        { date_header_name, escher_date_header },
                        { "Host", "mockbin:8080" }
                    }
                })

                assert("dummy_key_v1" == api_key, err)
            end)

            context("when customer_id_header is given", function()
                it("should use path to sign request", function()
                    plugin_config.path_pattern = "/api/customers/{customer_id}/{path}"
                    plugin_config.customer_id_header = "X-Suite-Customerid"

                    get_response_body(TestHelper.setup_plugin_for_service(service.id, "escher-signer", plugin_config))

                    local raw_response = assert(helpers.proxy_client():send({
                        method = "GET",
                        path = "/anything/something",
                        headers = {
                            ["X-Suite-Customerid"] = "112233"
                        }
                    }))

                    local response = assert.res_status(200, raw_response)
                    local body = cjson.decode(response)

                    local auth_header_name = plugin_config.auth_header_name
                    local date_header_name = plugin_config.date_header_name

                    local escher_auth_header = body.headers[string.lower(auth_header_name)]
                    local escher_date_header = body.headers[string.lower(date_header_name)]

                    local api_key, err = escher_authenticate({
                        method = "GET",
                        url = "/api/customers/112233/something",
                        headers = {
                            { auth_header_name, escher_auth_header },
                            { date_header_name, escher_date_header },
                            { "Host", "mockbin:8080" }
                        }
                    })

                    assert("dummy_key" == api_key, err)
                end)
            end)
        end)
    end)
end)
