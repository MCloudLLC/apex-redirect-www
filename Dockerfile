FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/apex-redirect . \
    && mkdir -p /out/state && chmod 0700 /out/state && chown 10001:10001 /out/state

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/apex-redirect /apex-redirect
COPY --from=build --chown=10001:10001 /out/state /var/lib/apex-redirect
USER 10001:10001
ENV HTTP_ADDR=127.0.0.1:8080 ASK_ADDR=127.0.0.1:8081 STATE_PATH=/var/lib/apex-redirect/state.db
ENTRYPOINT ["/apex-redirect"]
