import type { Playbook } from "../playbook";
import { compose, REPORTING } from "./shared";

export const mobile: Playbook = {
	id: "agent.mobile",
	title: "Mobile app security review (MASVS)",
	summary:
		"OWASP MASVS-oriented review of mobile source or decompiled output: token storage, network security and pinning, deep links, WebViews and JS bridges, logging, platform permissions.",
	categories: ["security", "privacy"],
	targets: ["mobile"],
	needs: ["code", "shell"],
	checklist: [
		"Identified platform(s) and framework (native Android/iOS, React Native, Expo, Flutter, Capacitor/Cordova) and where source or decompiled output lives",
		"MASVS-STORAGE: checked where tokens, credentials and personal data are stored (SharedPreferences, UserDefaults, AsyncStorage, files, SQLite vs Keychain/Keystore/EncryptedSharedPreferences/SecureStore)",
		"MASVS-STORAGE: checked logs, crash reports, clipboard, screenshots/backgrounding and backups (android:allowBackup) for sensitive data",
		"MASVS-NETWORK: checked cleartext traffic settings (usesCleartextTraffic, network_security_config, NSAppTransportSecurity exceptions)",
		"MASVS-NETWORK: checked TLS validation overrides and certificate pinning implementation where the threat model needs it",
		"MASVS-PLATFORM: checked exported components, intent filters and deep links / universal links for unvalidated parameters and auth bypass",
		"MASVS-PLATFORM: checked WebView settings (JavaScript, file access, universal file access, JS bridges/addJavascriptInterface/postMessage handlers) and which URLs they load",
		"MASVS-CRYPTO: checked for hard-coded keys, weak algorithms and insecure randomness",
		"MASVS-AUTH: checked biometric/local auth is bound to a cryptographic operation where it protects secrets, and session handling on the client",
		"MASVS-CODE: checked debuggable flags, test/debug endpoints, and dangerous permissions relative to features",
		"Checked third-party SDKs for data collection and secrets embedded in the app (API keys for backend services)",
	],
	instructions: compose(
		`# Mobile app security review (OWASP MASVS)

## Scope

Mobile app source code (native Android/Kotlin/Java, iOS/Swift/Objective-C, React Native/Expo, Flutter, Capacitor/Cordova/Ionic) and configuration: \`AndroidManifest.xml\`, \`network_security_config.xml\`, Gradle files, \`Info.plist\`, entitlements, \`app.json\`/\`app.config.*\`, \`capacitor.config.*\`, \`pubspec.yaml\`. If the target is a binary (\`.apk\`, \`.aab\`, \`.ipa\`) and your environment offers a read-only shell, you can list and read archive entries (e.g. \`unzip -l\`, \`unzip -p <file> <entry>\`); without one, or for compiled code, you need decompiled output — if the user has decompiled output (jadx/apktool) in the workspace, review that. State clearly what you could and could not inspect.

Backend APIs are out of scope except where the app embeds secrets for them or disables protections when talking to them.

## Method

1. **Orient.** Identify platforms, framework and build variants (debug vs release config). Find the manifest/plist, networking layer, auth/session code, storage helpers, WebView usage, deep-link routing, and third-party SDK initialisation.
2. **MASVS-STORAGE.** Find where access/refresh tokens, credentials, PII and keys are persisted. Plain \`SharedPreferences\`, \`NSUserDefaults\`, React Native \`AsyncStorage\`, MMKV without encryption, SQLite/Realm, files in external storage or the Documents directory are unsuitable for secrets — expect Keychain/Keystore, \`EncryptedSharedPreferences\`, \`expo-secure-store\`, \`react-native-keychain\`, \`flutter_secure_storage\`. Check logging (\`Log.d\`, \`print\`, \`NSLog\`, \`console.log\` in release builds) of tokens and personal data, \`android:allowBackup\`/\`fullBackupContent\` including sensitive files, sensitive screens not protected from screenshots/app-switcher snapshots (\`FLAG_SECURE\`) where the app's threat model warrants it, and clipboard use for secrets.
3. **MASVS-NETWORK.** Check \`android:usesCleartextTraffic\`, \`network_security_config\` (cleartext permitted, user CAs trusted in release, debug-overrides leaking into release), iOS ATS exceptions (\`NSAllowsArbitraryLoads\`, per-domain exceptions). Find custom \`TrustManager\`/\`HostnameVerifier\`/\`URLSessionDelegate\`/\`badCertificateCallback\` implementations that accept all certificates. For high-risk apps (finance, health, enterprise), check whether certificate/public-key pinning is implemented correctly (backup pins, pin on the right hosts) — absence is a finding only when the app's risk profile calls for it.
4. **MASVS-PLATFORM.** Enumerate exported activities/services/receivers/providers and their permissions; intent filters and custom URL schemes; universal/app links (\`autoVerify\`, associated domains). For each deep-link handler, check whether URL parameters are validated before navigation, loading into WebViews, or performing actions (auth bypass, open redirect, token leakage via \`redirect_uri\`). Check \`PendingIntent\` mutability and implicit intents carrying sensitive data.
5. **WebViews.** For each WebView: \`setJavaScriptEnabled\`, \`setAllowFileAccess\`, \`setAllowFileAccessFromFileURLs\`/\`setAllowUniversalAccessFromFileURLs\`, \`addJavascriptInterface\` (what methods are exposed and to which origins), \`WKScriptMessageHandler\` / React Native WebView \`onMessage\` / \`injectedJavaScript\` handlers, \`originWhitelist\`, \`mixedContentMode\`, and whether untrusted or attacker-influenced URLs can be loaded (deep links, push payloads). A JS bridge exposed to arbitrary origins is a high-severity issue.
6. **MASVS-CRYPTO.** Hard-coded encryption keys/IVs, ECB mode, MD5/SHA-1 for security purposes, \`Math.random\`/\`java.util.Random\` for tokens, custom crypto.
7. **MASVS-AUTH.** Biometric prompts that only gate UI (boolean callback) while the secret is stored unprotected, instead of unlocking a Keystore/Keychain key (\`CryptoObject\`, \`kSecAccessControlBiometryCurrentSet\`); tokens never refreshed/revoked on logout; client-side-only authorization decisions.
8. **MASVS-CODE & RESILIENCE.** \`android:debuggable\` in release, debug menus/endpoints reachable in production builds, outdated SDK versions with known issues (\`minSdkVersion\` very low), dangerous permissions not justified by features (SMS, contacts, location always, accessibility services).
9. **Embedded secrets & SDKs.** Backend secrets embedded in the app (anything granting more than a public client should have), third-party SDKs collecting device identifiers/location without consent gating.

## Severity rubric

- **critical** — embedded backend secret granting privileged access, JS bridge exposing sensitive native functionality to arbitrary web content, TLS validation disabled in release builds.
- **high** — tokens/credentials stored unencrypted, deep link that performs authenticated actions or leaks tokens without validation, exported component exposing sensitive data/actions, cleartext traffic allowed for API hosts in release.
- **medium** — sensitive data in logs in release builds, \`allowBackup\` with sensitive data, WebView file access enabled with untrusted content, missing pinning in a high-risk app, biometric auth not bound to crypto.
- **low** — hygiene issues: overly broad permissions, debug config remnants without impact, weak hashing for non-security purposes.
- **info** — observations and items you could not verify from available artifacts.

Reference MASVS controls (e.g. https://mas.owasp.org/MASVS/) and relevant CWE in \`references\`.

## What NOT to report

- Missing anti-tamper, root/jailbreak detection or obfuscation as standalone findings unless the app's threat model clearly requires them (MASVS-RESILIENCE is optional for most apps).
- Missing certificate pinning in ordinary consumer apps without elevated risk.
- Public client identifiers (Firebase config, Google Maps keys restricted by app signature, OAuth client ids).
- Debug-only code paths guarded by build-type checks that are stripped from release.`,
		REPORTING,
	),
};
