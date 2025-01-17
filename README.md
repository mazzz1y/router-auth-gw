# Router Auth Gateway

Authentication gateway for router devices.

## Features

With this tool, you can:

- Bypass router authentication.
- Use basic authentication instead of proprietary authentication mechanisms for your router.
- Utilize SSO for all of your devices and map your OAuth users to internal router users (using forwarded auth headers).
- Expose only a single endpoint (e.g., for Wake-on-LAN).

Currently supported devices:
- [Keenetic](https://keenetic.com)
- [GL.iNet](https://www.gl-inet.com)

This app is a fork of `keenetic-auth-gw`, and I decided to add support for other devices. It is open for PRs for additional device support.

*I created this app for personal use, so there may be some issues or inconsistencies, and the design can change at any time*

## Usage
### Docker
```yaml
services:
  router-auth-gw:
    image: "ghcr.io/mazzz1y/router-auth-gw:latest"
    ports:
      - 8080:8080
    volumes:
      - "./config.yaml:config.yaml"
```
### Configuration

```yaml
entrypoints:
  - listen: "127.0.0.1:8080"
    device_tag: keenetic-home
    basic_auth:
      - username: xxx
        password: xxx
    allowed_endpoints:
      - /rci/ip/hotspot/wake

  - listen: "127.0.0.1:8081"
    device_tag: keenetic-home
    read_only: true # Allows only GET requests

  - listen: "127.0.0.1:8082"
    device_tag: glinet-remote
    # For use with OAuth2 Proxy, Authelia, and other authorization proxies.
    # Requests with a valid username in the header will be forwarded without additional authorization.
    # If the username is not valid, a 403 error will be returned.
    forward_auth:
      header: X-Forwarded-User
      # Mapping of incoming usernames to internal usernames.
      # For example, the user coming from the header 'mazzz1y' will be logged as the 'root' internal user.
      mapping:
        mazzz1y: root
    bypass_auth_endpoints:
      - /favicon.ico

devices:
  - tag: keenetic-home
    url: http://192.168.1.1
    proxy_url: socks5://127.0.0.1:1085
    # Users are primarily for entry points with forwarded auth header.
    # In other cases, the first user in the list will be used.
    users:
      - username: admin
        password: xxx
      - username: user
        password: xxx

  - tag: glinet-remote
    url: https://remote-glinet.com
    # Users are primarily for entry points with forwarded auth header.
    # In other cases, the first user in the list will be used.
    users:
      - username: admin
        password: xxx
```