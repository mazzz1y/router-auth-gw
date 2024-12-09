# Keenetic Auth Gateway

Authentication gateway for Keenetic devices.

## Features

This app provides numerous options and supports multiple devices for complex configurations.

- **Multiple Server Instances**: Supports multiple entry points, each listening on different local ports with unique settings.
- **Authentication Methods**: Includes basic authentication and forwarded authentication headers, enabling integration with OAuth2 Proxy, Authelia, Authentik, and other SSO solutions.
- **Device Configuration**: Supports multiple device configurations.
- **Proxy**: Configurable HTTP/SOCKS proxy for each device or globally via http_proxy variables

## Usage
### Docker
```yaml
services:
  keenetic-auth-gw:
    image: "ghcr.io/mazzz1y/keenetic-auth-gw:latest"
    ports:
      - 8080:8080
    volumes:
      - "./config.yaml:config.yaml"
```
### Configuration

```yaml
entrypoints:
  - listen: "127.0.0.1:8080"
    device_tag: keenetic
    basic_auth:
      - username: xxx
        password: xxx
    allowed_endpoints:
      - /rci/ip/hotspot/wake

  - listen: "127.0.0.1:8081"
    device_tag: keenetic
    read_only: true # Allows only GET requests

  - listen: "127.0.0.1:8082"
    device_tag: keenetic-remote
    # For use with OAuth2 Proxy, Authelia, and other authorization proxies.
    # Requests with a valid username in the header will be forwarded without additional authorization.
    # If the username is not valid, a 403 error will be returned.
    forward_auth:
      header: X-Forwarded-User
      # Mapping of incoming usernames to internal usernames.
      # For example, the user coming from the header 'mazzz1y' will be logged as the 'admin' internal user.
      mapping:
        mazzz1y: admin

devices:
  - tag: keenetic-home
    url: http://192.168.1.1
    proxy_url: socks5://127.0.0.1:1085
    users:
      - username: admin
        password: xxx

  - tag: keenetic-remote
    url: https://remote-keenetic.com
    # Users are primarily for entry points with forwarded auth header.
    # In other cases, the first user in the list will be used.
    users:
      - username: admin
        password: xxx
      - username: user
        password: xxx
```