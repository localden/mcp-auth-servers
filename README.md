# 🔒 MCP Server Authentication Reference Collection

Reference servers that demo how authentication works with the current [Model Context Protocol spec](https://spec.modelcontextprotocol.io/specification/2025-03-26/basic/authorization/).

>[!WARNING]
>Code presented here is for **demo purposes only**. Your specific scenarios (including rules inside your enterprise, specific security controls, or other protection mechanisms) may differ from the ones that are outlined in this repository. **Always** conduct a security audit and threat modeling for any production and customer-facing assets that require authentication and authorization.

## Scenarios

Servers above are designed for various runtime scenarios. They are tagged as follows:

- Remote MCP servers: ![Remote MCP Server](https://img.shields.io/badge/MCP%20Server-Remote-blue)
- Local MCP servers: ![Local MCP Server](https://img.shields.io/badge/MCP%20Server-Local-green)
- Dual-purpose MCP servers (_can run locally or remotely_): ![Dual-purpose MCP Server](https://img.shields.io/badge/MCP%20Server-Dual-cyan)

## Supported identity providers

| Provider | Scenario | Server Type | Implementation | State |
|:---------|:---------|:------------|:---------------|:------|
| Entra ID | Confidential client, mapped to session token. | ![Dual-purpose MCP Server](https://img.shields.io/badge/MCP%20Server-Dual-cyan) | [`entra-id-cca-session`](/src/entra-id-cca-session/) | ![State: Prototype](https://img.shields.io/badge/State-Prototype-orange) |
| Entra ID | Public client, using WAM | ![Local MCP Server](https://img.shields.io/badge/MCP%20Server-Local-green) | [`entra-id-local-wam`](/src/entra-id-local-wam/) | ![State: Prototype](https://img.shields.io/badge/State-Prototype-orange) |
| GitHub   | GitHub application w/OAuth, mapped to session token. | ![Dual-purpose MCP Server](https://img.shields.io/badge/MCP%20Server-Dual-cyan) | [`github-app-session`](/src/github-app-session/) | ![State: Prototype](https://img.shields.io/badge/State-Prototype-orange) |
