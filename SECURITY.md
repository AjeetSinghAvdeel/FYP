# Security Model and Limitations

This prototype is intended for authorized local laboratory use only.

- Target registration rejects public targets by default. `ALLOW_PUBLIC_TARGETS=true` is an explicit opt-in and does not establish authorization.
- Tool execution accepts structured adapter inputs and never executes model-generated shell strings.
- The policy layer checks target scope and approved tools before execution.
- Mock execution is the default and is labelled in tool results and the UI.
- Passwords are hashed and API endpoints use JWT bearer authentication.
- LLM responses are untrusted recommendations. They cannot change scope, budgets, numerical risk scores, or adapter commands.
- Real execution must be isolated by the operator. This repository does not provide a container sandbox or network egress firewall.
- The current audit and database model are prototype-level and do not yet provide append-only hash chaining, migrations, or production secret rotation.
- Do not use this system against a target without written authorization.
