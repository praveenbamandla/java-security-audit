# FIPS Audit Provider

A zero-touch JCA Security Provider that intercepts and logs all non-FIPS
cryptographic usage in any Java application -- without modifying application
code, classpath, or startup arguments.

## How It Works

`FipsAuditProvider` registers at JCA position 1 and intercepts every
`getInstance()` call. It **never** processes any cryptographic operation
itself -- it only observes, logs, and returns `null` so JCA falls through
to the real native providers (SUN, SunJCE, etc.).

Two audit layers classify each call:

| Layer | Source | What it detects | Required |
|-------|--------|-----------------|----------|
| **Layer 1** | BCFIPS oracle | Algorithms rejected by BCFIPS in approved-only mode (MD5, DES, RC4, etc.) | Optional (bc-fips JAR) |
| **Layer 2** | Policy file | WEAK/DISALLOWED configurations per `fips-policy.properties` (AES/ECB, SHA-1, 3DES, etc.) | Always active |

If Layer 1 is unavailable (no bc-fips JAR), only Layer 2 applies.

---

## Prerequisites

| Component | Version | Notes |
|-----------|---------|-------|
| JDK       | 21      | Must match the target JRE's exact version for `jlink` |
| Maven     | 3.8+    | |

---

## Downloading bc-fips-2.0.0.jar

The Bouncy Castle FIPS JAR is **not bundled** in this project.

```bash
# Maven (downloads to target/dependency/)
cd auditor_app
mvn dependency:copy-dependencies -DincludeArtifactIds=bc-fips -DoutputDirectory=target/dependency

# Or direct download
curl -O https://repo1.maven.org/maven2/org/bouncycastle/bc-fips/2.0.0/bc-fips-2.0.0.jar
```

> **Important:** Do NOT repackage `bc-fips-2.0.0.jar` into a fat/uber JAR.
> Bouncy Castle FIPS performs a self-integrity checksum; repackaging breaks it.

---

## Build

```bash
cd auditor_app
mvn clean package
```

Output: `auditor_app/target/fips-audit-provider.jar` (modular JAR with `module-info.class`)

To also download the bc-fips dependency:

```bash
mvn clean package dependency:copy-dependencies -DincludeArtifactIds=bc-fips -DoutputDirectory=target/dependency
```

Verify the module descriptor:

```bash
jar --describe-module --file=target/fips-audit-provider.jar
```

Expected output:

```
com.demo.fips.audit@1.0-SNAPSHOT
exports com.demo.fips.audit
requires java.base
requires java.instrument
requires java.logging
provides java.security.Provider with com.demo.fips.audit.FipsAuditProvider
```

---

## Deployment

### Option A: JRE Patch (recommended for JNI-embedded apps)

Use this when the application is launched by a native C++ executable via
`JNI_CreateJavaVM` and you cannot pass `-javaagent` or `JAVA_TOOL_OPTIONS`.

The `patch-jre.ps1` script uses `jlink` to embed the audit module directly
into the application's shipped JRE. After patching, FIPS auditing is active
for every application using that JRE -- zero arguments, zero env vars.

**Requirements:**
- A full JDK (with `jmods/` directory) matching the target JRE's exact version
- Write access to the target JRE directory

**Run:**

```powershell
.\patch-jre.ps1 `
    -JdkHome   "C:\apps\java\jdk-21.0.7+6" `
    -TargetJre "C:\MyApp\jre" `
    -AuditJar  "C:\repos\jfips\auditor_app\target\fips-audit-provider.jar" `
    -BcfipsJar "C:\repos\jfips\auditor_app\target\dependency\bc-fips-2.0.0.jar"
```

Omit `-BcfipsJar` to deploy with Layer 2 (policy rules) only.

**What the script does:**

1. Discovers all modules in the target JRE
2. Runs `jlink` to create a new JRE image with the audit module added
3. Edits `java.security` to register `FipsAuditProvider` at position 1
4. Copies `bc-fips-2.0.0.jar` into `lib/fips/` (if provided)
5. Copies `fips-audit.properties` and `fips-policy.properties` into `conf/`
6. Backs up the original JRE (`.backup` suffix) and swaps in the new one

**Resulting JRE layout:**

```
<patched-jre>/
  bin/java.exe
  conf/
    fips-audit.properties          <-- audit config (log path, depth, dedupe)
    fips-policy.properties         <-- algorithm rules (WEAK/DISALLOWED)
    security/
      java.security                <-- FipsAuditProvider at position 1
  lib/
    fips/
      bc-fips-2.0.0.jar           <-- BCFIPS oracle (unmodified)
    modules                        <-- includes com.demo.fips.audit
```

**Rollback:**

```powershell
# Remove patched JRE and restore backup
Remove-Item -Recurse -Force "C:\MyApp\jre"
Rename-Item "C:\MyApp\jre.backup" "jre"
```

---

### Option B: Java Agent (for standard java launches)

Use this when the application is started with a normal `java` command and
you can pass arguments or set environment variables.

**Windows (cmd):**

```cmd
set "JAVA_TOOL_OPTIONS=-javaagent:C:\path\to\fips-audit-provider.jar -Dorg.bouncycastle.fips.approved_only=true -Dfips.audit.log=C:\path\to\fips-audit.log -Dfips.audit.stack.depth=30 -Dfips.audit.dedupe=true -Xbootclasspath/a:C:\path\to\bc-fips-2.0.0.jar"
```

**Linux / macOS:**

```bash
export JAVA_TOOL_OPTIONS="\
  -javaagent:/path/to/fips-audit-provider.jar \
  -Dorg.bouncycastle.fips.approved_only=true \
  -Dfips.audit.log=/var/log/fips-audit.log \
  -Dfips.audit.stack.depth=30 \
  -Dfips.audit.dedupe=true \
  -Xbootclasspath/a:/path/to/bc-fips-2.0.0.jar"
```

Then start the application normally. The JVM picks up `JAVA_TOOL_OPTIONS`
automatically.

> **Why not `-Djava.security.properties`?**
> Manipulating `java.security` via properties files is fragile:
> double `=` replaces the entire file (breaks SSL/TLS), single `=` can
> conflict with some JDK distributions. The agent avoids both problems.

---

## Configuration

All settings are resolved in order: **system property > config file > default**.

In JRE patch mode, edit `<java.home>/conf/fips-audit.properties`.
In agent mode, pass `-D` flags.

### fips-audit.properties

| Property | Default | Description |
|----------|---------|-------------|
| `fips.audit.log` | `fips-audit.log` | Absolute or relative path for the audit log file. Relative paths resolve against the application's working directory. |
| `fips.audit.stack.depth` | `20` | Max application stack frames per log entry. Set to `0` for no limit. |
| `fips.audit.dedupe` | `true` | When `true`, each unique violation (classification + type + algorithm + caller site) is logged once per JVM lifetime. Set to `false` to log every occurrence. |

To change settings after patching, edit the file directly in the JRE --
no rebuild or re-patch needed. Changes take effect on the next JVM startup.

### fips-policy.properties

Defines algorithm-level rules beyond what BCFIPS enforces.

**Format:**

```properties
<type>.<algorithm>[.<mode>][.<padding>] = APPROVED | WEAK | DISALLOWED [| reason]
```

**Lookup order (most specific wins):**

1. `Cipher.AES.ECB.NoPadding` (full match)
2. `Cipher.AES.ECB` (mode match)
3. `Cipher.AES` (algorithm match)
4. No match -- defer to BCFIPS probe result

**Example rules:**

```properties
Cipher.AES.ECB       = WEAK | ECB mode leaks block-level patterns (NIST SP 800-38A)
Cipher.DESede        = WEAK | 3DES deprecated by NIST after 2023 (SP 800-131A Rev 2)
MessageDigest.SHA-1  = WEAK | SHA-1 deprecated for signatures (NIST SP 800-131A Rev 2)
Signature.SHA1withRSA = WEAK | SHA-1 deprecated for signatures
```

To update rules after patching, edit `<java.home>/conf/fips-policy.properties`
directly. No rebuild or re-patch needed.

---

## Audit Log Output

Each violation produces an entry like:

```
FIPS AUDIT - DISALLOWED
  Timestamp : 2026-02-28T15:30:00.123Z
  JCA type  : Cipher
  Algorithm : DES/ECB/PKCS5Padding
  Reason    : Algorithm not available in BCFIPS approved-only mode
  Caller stack (application frames):
    at com.myapp.crypto.LegacyEncryptor.encrypt(LegacyEncryptor.java:45)
    at com.myapp.service.DataService.process(DataService.java:112)
```

---

## JRE Patch vs Agent -- When to Use Which

| Scenario | Recommended approach |
|----------|---------------------|
| C++ exe launches JVM via `JNI_CreateJavaVM` | **JRE Patch** |
| Standard `java -jar app.jar` | Agent (simpler) |
| Cannot modify the JRE directory | Agent |
| Need zero-config deployment across machines | **JRE Patch** (ship the patched JRE) |
| App crashes with BCFIPS on bootclasspath | **JRE Patch** (isolates BCFIPS in URLClassLoader) |

---

## Why JRE Patch Is Safer Than Bootclasspath

When `bc-fips.jar` is on the bootclasspath (`-Xbootclasspath/a`), it shares
the same classloader as JCA. During BCFIPS construction, its internal
`SecureRandom.getInstance()` call can trigger recursive JCA provider
resolution, causing intermittent `StackOverflowError` or deadlocks.

The JRE patch loads BCFIPS via an isolated `URLClassLoader` from
`<java.home>/lib/fips/`. This means:

- BCFIPS is invisible to JCA's provider chain
- Its internal JCA calls resolve against native providers, never reaching
  FipsAuditProvider
- No recursive calls, no deadlocks, no intermittent crashes

---

## Project Structure

```
auditor_app/
  pom.xml                              Maven build (produces modular JAR)
  security-audit.properties            Legacy JCA config (not used in patch mode)
  src/main/java/
    module-info.java                   JPMS module descriptor
    com/demo/fips/audit/
      FipsAuditProvider.java           JCA provider + agent entry points
      FipsPolicy.java                  Policy engine (reads fips-policy.properties)
  src/main/resources/
    fips-audit.properties              Audit configuration template
    fips-policy.properties             Algorithm policy rules template

demo_app/
  CryptoDemo.java                      Test app exercising weak & strong algorithms

patch-jre.ps1                          PowerShell script to patch a JRE with jlink
```

---

## Testing with the Demo App

```bash
cd demo_app
javac CryptoDemo.java
```

**With patched JRE:**

```cmd
"C:\MyApp\jre\bin\java" CryptoDemo
```

**With agent:**

```cmd
java -javaagent:..\auditor_app\target\fips-audit-provider.jar ^
     -Xbootclasspath/a:..\auditor_app\target\dependency\bc-fips-2.0.0.jar ^
     CryptoDemo
```

Check `fips-audit.log` for violations.

---

## Re-patching After Code Changes

1. Rebuild: `cd auditor_app && mvn clean package`
2. Restore backup: rename `<jre>.backup` back to `<jre>`
3. Re-run `patch-jre.ps1` with the same parameters
