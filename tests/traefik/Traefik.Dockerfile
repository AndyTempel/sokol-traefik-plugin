FROM traefik:v3.7.9@sha256:652929a140a32d7cafafb13c6cdfab5376cfeff800f51397b87b524501ed02a8

COPY . /plugins-local/src/git.ksoft.tech/ksoft/sokol-traefik-plugin
COPY tests/traefik/static.yml /etc/traefik/static.yml
COPY tests/traefik/dynamic.yml /etc/traefik/dynamic.yml
COPY pages /pages
COPY --chmod=0600 tests/traefik/token.fixture /run/secrets/sokol-plugin-token

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--configFile=/etc/traefik/static.yml"]
