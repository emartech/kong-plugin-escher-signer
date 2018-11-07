FROM emarsys/kong-dev-docker:a1a962b1ca0db94bfd69afaf75f1fb7f8b63a585

RUN luarocks install classic
RUN luarocks install lua-easy-crypto 1.0.0
RUN luarocks install kong-lib-logger --deps-mode=none
