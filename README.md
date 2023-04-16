<img src="doc/img/eu_regional_development_fund_horizontal.jpg" width="350" height="200" alt="European Union European Regional Development Fund"/>

# GovSSO Incoming Proxy

GovSSO Incoming Proxy routes and filters inbound HTTP requests to Ory Hydra and GovSSO Session.

## Prerequisites

* Java 17 JDK

## Building and Running Locally

1. Follow [GOVSSO-Session/README.md](https://github.com/e-gov/GOVSSO-Session/blob/master/README.md) to run dependent
   services.
2. If you have generated new TLS certificates (doable at project GOVSSO-Session) after the last copy, then:
    * copy-replace `GOVSSO-Session/local/tls/inproxy/*.p12` files to `src/main/resources`;
    * copy-replace `GOVSSO-Session/local/tls/admin/admin.localhost.keystore.p12`
      and `GOVSSO-Session/local/tls/hydra/hydra.localhost.keystore.p12` and
      `GOVSSO-Session/local/tls/session/session.localhost.keystore.p12` to `src/test/resources`.
3. Add `127.0.0.1 admin.localhost hydra.localhost session.localhost` line to `hosts` file. This is needed only for
   requests originating from GOVSSO-InProxy when it's running locally (not in Docker Compose). It's not needed for web
   browsers as popular browsers already have built-in support for resolving `*.localhost` subdomains.
4. Run
   ```shell 
   ./mvnw spring-boot:run
   ```

## Running in Docker

1. Build
    * Either build locally
      ```shell
      ./mvnw spring-boot:build-image
      ```
    * Or build in Docker
      ```shell
      docker run --pull always --rm \
                 -v /var/run/docker.sock:/var/run/docker.sock \
                 -v "$HOME/.m2:/root/.m2" \
                 -v "$PWD:/usr/src/project" \
                 -w /usr/src/project \
                 maven:3.8-openjdk-17 \
                 mvn spring-boot:build-image
      ```
      Git Bash users on Windows should add `MSYS_NO_PATHCONV=1` in front of the command.
2. Follow GOVSSO-Session/README.md to run GOVSSO-InProxy and dependent services inside Docker Compose

## Endpoints

* https://inproxy.localhost:13443/actuator - maintenance endpoints

## Configuration

### Integration with GovSSO Admin

| Parameter | Mandatory | Description | Example |
| :-------- | :-------- | :---------- | :------ |
| `govsso-inproxy.admin.base-url` | Yes | GovSSO Admin administrative API base URL. | `https://admin.localhost:17443/` |
| `govsso-inproxy.admin.tls.trust-store` | Yes | Location of trust-store, containing trust anchors (CA or end-entity certificates) for verifying TLS connections to GovSSO Admin. | `classpath:path/to/trust-store.p12` or `file:/path/to/trust-store.p12` |
| `govsso-inproxy.admin.tls.trust-store-password` | Yes | Trust-store password. | `changeit` |
| `govsso-inproxy.admin.tls.trust-store-type` | No | Trust-store type. If not provided, defaults to `PKCS12`. | `PKCS12` |

### Integration with Ory Hydra

| Parameter | Mandatory | Description | Example |
| :-------- | :-------- | :---------- | :------ |
| `govsso-inproxy.hydra.base-url` | Yes | Ory Hydra public API base URL. | `https://hydra.localhost:14443/` |
| `govsso-inproxy.hydra.tls.trust-store` | Yes | Location of trust-store, containing trust anchors (CA or end-entity certificates) for verifying TLS connections to Ory Hydra. | `classpath:path/to/trust-store.p12` or `file:/path/to/trust-store.p12` |
| `govsso-inproxy.hydra.tls.trust-store-password` | Yes | Trust-store password. | `changeit` |
| `govsso-inproxy.hydra.tls.trust-store-type` | No | Trust-store type. If not provided, defaults to `PKCS12`. | `PKCS12` |

### Integration with GovSSO Session

| Parameter | Mandatory | Description | Example |
| :-------- | :-------- | :---------- | :------ |
| `govsso-inproxy.session.base-url` | Yes | GovSSO Session public API base URL. | `https://session.localhost:15443/` |
| `govsso-inproxy.session.tls.trust-store` | Yes | Location of trust-store, containing trust anchors (CA or end-entity certificates) for verifying TLS connections to GovSSO Session. | `classpath:path/to/trust-store.p12` or `file:/path/to/trust-store.p12` |
| `govsso-inproxy.session.tls.trust-store-password` | Yes | Trust-store password. | `changeit` |
| `govsso-inproxy.session.tls.trust-store-type` | No | Trust-store type. If not provided, defaults to `PKCS12`. | `PKCS12` |

## Non-pom.xml Licenses

* [Maven Wrapper](https://maven.apache.org/wrapper/) - Apache 2.0 license
