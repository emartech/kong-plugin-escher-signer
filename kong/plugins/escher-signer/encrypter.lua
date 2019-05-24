local Object = require "classic"
local EasyCrypto = require "resty.easy-crypto"

local Encrypter = Object:extend()

function Encrypter:new(encryption_key)
    self.encryption_key = encryption_key

    self.crypto = EasyCrypto:new({
        saltSize = 12,
        ivSize = 16,
        iterationCount = 10000
    })
end

function Encrypter:encrypt(subject)
    return self.crypto:encrypt(self.encryption_key, subject)
end

function Encrypter:decrypt(subject)
    return self.crypto:decrypt(self.encryption_key, subject)
end

function Encrypter.create_from_file(file_path)
    local file = io.open(file_path, "r")
    local encryption_key = file:read("*all")

    file:close()

    return Encrypter(encryption_key)
end

return Encrypter