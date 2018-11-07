FROM emarsys/kong-dev-docker:a1a962b1ca0db94bfd69afaf75f1fb7f8b63a585

RUN apk update
RUN apk add \
    cmake \
    g++ \
    openssl-dev

RUN luarocks install date 2.1.2-1
RUN luarocks install classic 0.1.0-1
RUN luarocks install escher 0.2-17
RUN luarocks install lua-easy-crypto 1.0.0-1
RUN luarocks install kong-lib-logger 0.3.0-1 --deps-mode=none
