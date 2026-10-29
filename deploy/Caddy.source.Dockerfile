# Reproducible audit candidate, NOT an accepted release image.
# Unmodified stock Caddy, no plugins/forks. Published dependency fixes remove
# Alpine/stdlib/v4 findings, but CVE-2026-116587 HIGH (go-jose/v3 v3.0.5)
# remains unfixed and blocks release: DoS parsing RSA JWKs. Its actual importer is
# go.step.sm/crypto/jose. No vulnerability exceptions are permitted.
FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /work
RUN go mod init stock-caddy-check \
    && go get github.com/caddyserver/caddy/v2@v2.11.7 \
       golang.org/x/net@v0.62.0 github.com/go-jose/go-jose/v4@v4.1.6 go.step.sm/crypto@v0.91.1 \
    && CGO_ENABLED=0 go build -mod=mod -trimpath -ldflags="-s -w" -o /caddy github.com/caddyserver/caddy/v2/cmd/caddy
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /caddy /usr/bin/caddy
USER 10002:10002
ENTRYPOINT ["/usr/bin/caddy"]
