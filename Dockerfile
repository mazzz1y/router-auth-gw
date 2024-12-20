FROM golang:1.23-alpine3.21 AS build

ENV CGO_ENABLED=0
COPY . /app

ARG VERSION
RUN cd /app && \
  go build -ldflags="-s -w -X main.version=$VERSION" -trimpath -o /router-auth-gw ./cmd/router-auth-gw

FROM alpine:3.21
COPY --from=build /router-auth-gw /router-auth-gw
USER 1337

CMD ["/router-auth-gw", "-c", "config.yaml", "start"]
