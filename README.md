# 🔒 MCP Server Authentication Reference Collection

Reference servers that demo how authentication works with the current [Model Context Protocol spec](https://spec.modelcontextprotocol.io/specification/2025-03-26/basic/authorization/).

>[!WARNING]
>Code presented here is for **demo purposes only**. Your specific scenarios (including rules inside your enterprise, specific security controls, or other protection mechanisms) may differ from the ones that are outlined in this repository. **Always** conduct a security audit and threat modeling for any production and customer-facing assets that require authentication and authorization.

## Scenarios

Servers above are designed for various runtime scenarios. They are tagged as follows:

- Remote MCP servers: ![Remote MCP Server](https://img.shields.io/badge/MCP%20Server-Remote-blue)
- Local MCP servers: ![Remote MCP Server](https://img.shields.io/badge/MCP%20Server-Local-green)
- Dual-purpose MCP servers (can run locally or remotely): ![Remote MCP Server](https://img.shields.io/badge/MCP%20Server-Dual-cyan)

## Supported identity providers

| Provider | Scenario | Implementation | State | Notes |
|:---------|:---------|:---------------|:------|:------|
| Entra ID | Session-based authentication (confidential client, MCP client acquires session token) | [`entra-id-cca-session`](/src/entra-id-cca-session/) | ![State: Prototype](https://img.shields.io/badge/State-Prototype-orange) | |
| GitHub   | Session-based authentication (GitHub application w/OAuth, client acquires session token) | [`github-app-session`](/src/github-app-session/) | ![State: Prototype](https://img.shields.io/badge/State-Prototype-orange) | |
