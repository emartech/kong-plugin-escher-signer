FROM emarsys/kong-dev-docker:5fa91b6bb62e6a01d6a5a8782a8a550d4d7ec56d

RUN luarocks install classic
RUN luarocks install lua-easy-crypto 1.0.0
RUN luarocks install kong-lib-logger --deps-mode=none

COPY docker-entrypoint.sh /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/kong/bin/kong", "start", "--v"]
