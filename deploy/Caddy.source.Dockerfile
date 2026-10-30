# Reproducible stock Caddy build with no plugins or source forks.
# The scratch runtime removes unrelated Alpine packages, and explicit dependency
# updates pick up published fixes not yet present in the upstream binary image.
# The remaining no-fix go-jose/v3 advisory is governed by .trivyignore.yaml.
FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /work
COPY deploy/caddy-main.go.txt ./main.go
RUN go mod init stock-caddy-check \
    && go get github.com/caddyserver/caddy/v2@v2.11.7 \
       golang.org/x/net@v0.62.0 github.com/go-jose/go-jose/v4@v4.1.6 go.step.sm/crypto@v0.91.1 \
    && CGO_ENABLED=0 go build -mod=mod -trimpath -ldflags="-s -w" -o /caddy .
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /caddy /usr/bin/caddy
USER 0:0
ENTRYPOINT ["/usr/bin/caddy"]
