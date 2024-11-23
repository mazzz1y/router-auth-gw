FROM golang:1.23-alpine3.20 AS build

ENV CGO_ENABLED 0
COPY . /app

ARG VERSION
RUN cd /app && \
  go build -ldflags="-s -w -X main.version=$VERSION" -trimpath -o /keenetic-auth-gw ./cmd/keenetic-auth-gw

FROM alpine:3.20
COPY --from=build /keenetic-auth-gw /keenetic-auth-gw
USER 1337

CMD ["/keenetic-auth-gw", "-c", "config.yaml"]
