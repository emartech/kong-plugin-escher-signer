FROM emarsys/kong-dev-docker:a1a962b1ca0db94bfd69afaf75f1fb7f8b63a585

RUN apk update
RUN apk add \
    cmake \
    g++ \
    openssl-dev

RUN luarocks install classic
RUN luarocks install escher
RUN luarocks install lua-easy-crypto 1.0.0
RUN luarocks install kong-lib-logger --deps-mode=none
