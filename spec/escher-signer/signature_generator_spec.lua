local Escher = require "escher"
local SignatureGenerator = require "kong.plugins.escher-signer.signature_generator"

describe("SignatureGenerator", function()
    describe("#generate", function()
        it("should generate a valid Escher signature", function()
            local subject = SignatureGenerator({
                algo_prefix = "EMS",
                vendor_key = "EMS",
                hash_algo = "SHA256",
                auth_header_name = "X-Ems-Auth",
                date_header_name = "X-Ems-Date",
                additional_headers_to_sign = {}
            })

            local request = {
                method = "POST",
                url = "/some/path?query=param",
                headers = {
                    ["Host"] = "example.com",
                    ["X-Ems-Date"] = "20181107T105708Z"
                },
                body = '{"foo": "bar"}'
            }

            local signature = subject:generate(request, "test_key_v1", "v3ry53cr3t", "my/credential/scope")

            local escher = Escher:new({
                vendorKey = "EMS",
                algoPrefix = "EMS",
                hashAlgo = "SHA256",
                credentialScope = "my/credential/scope",
                authHeaderName = "X-Ems-Auth",
                dateHeaderName = "X-Ems-Date",
                date = "20181107T105708Z"
            })

            local api_key, err = escher:authenticate(
                {
                    method = "POST",
                    url = "/some/path?query=param",
                    headers = {
                        { "X-Ems-Auth", signature },
                        { "X-Ems-Date", "20181107T105708Z" },
                        { "Host", "example.com" }
                    },
                    body = '{"foo": "bar"}'
                }, function(key)
                    if key == "test_key_v1" then
                        return "v3ry53cr3t"
                    end

                    error("Escher key not found")
                end
            )

            assert.are.equal("test_key_v1", api_key, err)
        end)
    end)
end)
