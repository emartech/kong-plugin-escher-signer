FROM emarsys/kong-dev-docker:e5b638588a87cd6cb1b4bb52e6a09dae194a30d1

RUN apk update
RUN apk add \
    cmake \
    g++ \
    openssl-dev

RUN luarocks install classic 0.1.0-1
RUN luarocks install date 2.1.2-1
RUN luarocks install escher 0.2-17
RUN luarocks install kong-lib-logger 0.3.0-1 --deps-mode=none
RUN luarocks install lua-easy-crypto 1.0.0-1
