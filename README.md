# nats-iam-broker

A configurable NATS auth callout micro-service that exchanges Identity Provider (IdP) tokens for NATS user authorization JWTs, implementing the [decentralised auth callout](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_callout) flow.

1. A prospective NATS user authenticates with their IdP and passes the obtained token to NATS.
2. This micro-service validates the IdP token.
3. This micro-service mints a NATS user JWT with the appropriate authorizations.

## Features

- YAML-driven RBAC with Go template support
- Multiple IdP support with OIDC discovery
- Hot-reload configuration without restarts
- Prometheus metrics, health, and readiness endpoints
- Helm chart for Kubernetes deployments

## Quick Start

```bash
# Run with config files
nats-iam-broker serve env.yaml idp.yaml rbac.yaml

# With hot-reload and metrics
nats-iam-broker serve --watch --metrics env.yaml idp.yaml rbac.yaml
```

## Documentation

Full documentation is available at: https://jr200-labs.github.io/nats-iam-broker/

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the [MIT License](LICENSE).

## References

1. [Synadia Auth Callout (YouTube)](https://www.youtube.com/watch?v=VvGxrT-jv64)
2. [Synadia Decentralised Auth Callout (YouTube)](https://www.youtube.com/watch?v=5pQVjN0ym5w)
3. [NATS by Example: Decentralized Auth Callout](https://natsbyexample.com/examples/auth/callout-decentralized/cli)
