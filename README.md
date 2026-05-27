# ADT Auto-Logon

An Eclipse plugin that eliminates manual authentication popups in SAP ABAP Development Tools (ADT). Store your credentials once per project and the plugin handles logon automatically — for both Public Cloud and on-premise systems.

## Features

- **Credential storage** — Per-project username/password configuration via the standard Eclipse project properties dialog (right-click project > Properties > Auto-Logon). Credentials are stored in Eclipse Secure Storage.
- **Headless cloud authentication** — Replaces the browser-based IAS/SAML login popup with a background HTTP flow. No browser window, no manual interaction.
- **On-premise auto-logon** — Intercepts the password dialog for on-premise (basic auth) systems and injects stored credentials automatically.
- **Auto-login at startup** — Logs into all configured projects when Eclipse starts, so they're ready to use immediately.
- **Session keep-alive** — Periodic background pings prevent session timeouts during long editing sessions.

## Requirements

- Eclipse 2024-03 or later
- SAP ADT (ABAP Development Tools) installed
- Java 21+

## Installation

### From Update Site

1. In Eclipse, go to **Help > Install New Software...**
2. Add the update site URL: `https://koemaeda.github.io/adt-auto-logon/`
3. Select **ADT Auto-Logon** and follow the installation wizard
4. Restart Eclipse

### From Release ZIP

1. Download the latest p2 repository ZIP from [Releases](https://github.com/koemaeda/adt-auto-logon/releases)
2. In Eclipse, go to **Help > Install New Software...**
3. Click **Add... > Archive...** and select the ZIP
4. Select **ADT Auto-Logon** and follow the installation wizard
5. Restart Eclipse

## Usage

1. Right-click an ABAP project > **Properties** > **Auto-Logon**
2. Enter your username and password
3. Click **Apply and Close**

The plugin will handle authentication automatically from that point on. If stored credentials fail, it falls back to the standard SAP login dialog.

## Building from Source

### Prerequisites

- JDK 21+
- Maven 3.9+

### Build

```bash
mvn clean verify
```

This produces a p2 update site in `ninja.abap.adt_auto_logon.site/target/repository/` that you can install from using **Help > Install New Software... > Add... > Local...**.

### Development

Import into Eclipse as existing Maven projects. The Tycho build resolves dependencies from the Eclipse and SAP ADT p2 repositories configured in the parent POM.

## Technical Design

The plugin intercepts SAP ADT's authentication flow at multiple levels to cover all logon scenarios:

### Authentication Handler (Cloud + On-Premise HTTP)

Registers a custom `IHttpAuthenticationHandlerUi` via the `com.sap.adt.destinations.ui.httpAuthenticationHandlerUi` extension point for three authentication kinds: OAuth, SAML+Reentrance Ticket, and Basic Auth.

For **cloud systems**, the handler:
1. Creates the standard ADT browser-based logon facade (which starts a local Jetty server)
2. Drives the SAP Identity Authentication Service (IAS) login flow headlessly via HTTP — following redirects, submitting credentials, and handling SAML responses
3. Delivers the authentication token to the local Jetty server
4. The facade completes the token exchange and establishes the session

For **on-premise HTTP systems**, the handler injects the stored password into the volatile properties and calls `tryToConnect()` — the same mechanism the password dialog uses internally.

### Logon Service Wrapper (On-Premise)

Wraps the ADT `IAdtLogonService` singleton to intercept `ensureLoggedOn()` calls where the auth token is null (the trigger for the password dialog). When stored credentials exist, it constructs an authentication token from the stored password and delegates with a non-null token, bypassing the dialog entirely.

This is installed via reflection on `AdtLogonServiceFactory` during early startup and covers the `logOnInternalDestDataComplete` code path that bypasses the HTTP handler mechanism.

### Handler Installation

An `IStartup` early startup hook (`HandlerInstaller`) runs at Eclipse launch to:
1. Capture references to SAP's original authentication handlers for fallback delegation
2. Replace them in the internal factory cache with our handler
3. Wrap the logon service singleton with `AutoLogonService`

### Session Management

`SessionKeepAlive` sends periodic requests through the shared HTTP system connection to prevent session timeouts. `AutoLogonJob` triggers initial logon for all configured projects after Eclipse startup completes.

## Disclaimer

This plugin uses reflection to access internal ADT APIs that are not part of SAP's public API surface. While it includes fallback mechanisms for graceful degradation, future ADT updates may require adjustments. The plugin is provided as-is with no warranty.

## Acknowledgments

Development of this plugin was assisted by AI ([Claude Code](https://claude.ai/claude-code)).

## License

[Apache License 2.0](LICENSE)
