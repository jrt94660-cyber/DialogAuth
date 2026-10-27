# DialogAuth 1.1.0

Paper 26.1.x authentication plugin for offline-mode (cracked) Java servers. Uses native Minecraft dialogs for Java registration/login.

## Features
- Separate native dialog screens for registration and login.
- Password hashes use PBKDF2-HMAC-SHA256 with per-account random salts.
- Configurable session timeout (default 30 minutes) and failed-login limit.
- Optional automatic login for Floodgate-authenticated Bedrock players (requires Geyser + Floodgate).
- Optional premium Java auto-login when the joining UUID matches the Mojang profile UUID.
- Premium-name detection: if the claimed username exists on Mojang but the joining UUID is offline/cracked, the player is NOT auto-logged-in and must use DialogAuth registration/login.
- `/dialogauth reload`, `/dialogauth unregister <player>`, `/dialogauth login`.

## Premium login requirements
On an offline-mode server, install/configure a compatible premium-authentication solution such as FastLogin so successfully authenticated premium Java users join with their premium UUID. DialogAuth checks the Mojang profile for the username and compares UUIDs; a username existing on Mojang alone is never sufficient for premium auto-login. If Mojang's API is unreachable, premium auto-login is not granted and the player falls back to the normal password/session flow.

## Bedrock requirements
Install Geyser and Floodgate. DialogAuth detects Floodgate players through Floodgate's API at runtime and can auto-authenticate them. Without Floodgate, Bedrock auto-login is unavailable.

## Build
Requires Java 25 and Maven:
```sh
mvn -B clean package
```
Jar output: `target/DialogAuth-1.1.0.jar`.

## Important
Native dialog screens require a compatible Java client. Bedrock players are automatically authenticated and therefore do not need the Java dialog screen. Test on a staging server before production.
