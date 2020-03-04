return {
    postgres = {
        up = [[
              CREATE TABLE IF NOT EXISTS access_key(
                access_key text,
                secret text,
                encryption_key_path text,
                PRIMARY KEY (access_key)
              );
            ]],
    },
    cassandra = {
        up = [[
              CREATE TABLE IF NOT EXISTS access_key(
                access_key text,
                secret text,
                encryption_key_path text,
                PRIMARY KEY (access_key)
              );
            ]],
    },
}