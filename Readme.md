# FIPS Audit Project — Build Instructions

This project contains two independent components:

| Folder | Description | Output |
|--------|-------------|--------|
| `auditor_app/` | FIPS Audit JCA Provider — intercepts and logs non-FIPS crypto usage | `fips-audit-provider.jar` |
| `demo_app/` | Standalone crypto demo — exercises weak & strong algorithms for testing | `CryptoDemo.class` |

---

## Prerequisites

| Component | Version | Notes |
|-----------|---------|-------|
| JDK | 17+ (tested with 21) | Any distribution (Oracle, Temurin, Corretto, …) |
| Maven | 3.8+ | Required only for `auditor_app` |

---

## Downloading `bc-fips-2.0.0.jar`

The Bouncy Castle FIPS jar is **not bundled** in this project. Download it from one of these official sources:

| Source | URL |
|--------|-----|
| **Maven Central** | [bc-fips-2.0.0.jar](https://repo1.maven.org/maven2/org/bouncycastle/bc-fips/2.0.0/bc-fips-2.0.0.jar) |
| **Bouncy Castle website** | [bouncycastle.org/download/bouncy-castle-java-fips](https://www.bouncycastle.org/download/bouncy-castle-java-fips) |

**Direct download via command line:**

```bash
# Using curl
curl -O https://repo1.maven.org/maven2/org/bouncycastle/bc-fips/2.0.0/bc-fips-2.0.0.jar

# Using wget
wget https://repo1.maven.org/maven2/org/bouncycastle/bc-fips/2.0.0/bc-fips-2.0.0.jar

# Using Maven (downloads to local cache, then copy)
mvn dependency:copy -Dartifact=org.bouncycastle:bc-fips:2.0.0 -DoutputDirectory=.
```

> **Important:** Do **not** repackage `bc-fips-2.0.0.jar` into a fat/uber jar.
> Bouncy Castle FIPS performs a self-integrity checksum over its own jar bytes;
> repackaging corrupts the checksum and causes a `FipsOperationError` at runtime.

---

## 1. Build `auditor_app` (FIPS Audit Provider)

```bash
cd auditor_app
mvn clean package
```

This produces:

- `auditor_app/target/fips-audit-provider.jar` — the JCA audit provider
- `bc-fips-2.0.0.jar` is a **provided** dependency (not bundled); download it separately or copy from your Maven cache

To also copy the `bc-fips` dependency jar into `target/dependency/`:

```bash
cd auditor_app
mvn clean package dependency:copy-dependencies -DincludeArtifactIds=bc-fips -DoutputDirectory=target/dependency
```

### Using the Auditor

Attach to any Java application via `JAVA_TOOL_OPTIONS` (no code changes needed):

**Linux / macOS:**
```bash
export JAVA_TOOL_OPTIONS="\
  -Djava.security.properties==/path/to/security-audit.properties \
  -Dorg.bouncycastle.fips.approved_only=true \
  -Dfips.audit.log=/var/log/fips-audit.log \
  -Dfips.audit.stack.depth=30 \
  -Xbootclasspath/a:/path/to/fips-audit-provider.jar:/path/to/bc-fips-2.0.0.jar"
```

**Windows (cmd):**
```cmd
set "JAVA_TOOL_OPTIONS=-Djava.security.properties==C:\path\to\security-audit.properties -Dorg.bouncycastle.fips.approved_only=true -Dfips.audit.log=C:\path\to\fips-audit.log -Dfips.audit.stack.depth=30 -Xbootclasspath/a:C:\path\to\fips-audit-provider.jar;C:\path\to\bc-fips-2.0.0.jar"
```

**Windows (PowerShell):**
```powershell
$env:JAVA_TOOL_OPTIONS = @"
    -Djava.security.properties==C:\path\to\security-audit.properties
    -Dorg.bouncycastle.fips.approved_only=true
    -Dfips.audit.log=C:\path\to\fips-audit.log
    -Dfips.audit.stack.depth=30
    -Xbootclasspath/a:C:\path\to\fips-audit-provider.jar;C:\path\to\bc-fips-2.0.0.jar
"@
```

Then start your application normally — the JVM picks up the options automatically.
A copy of `security-audit.properties` is included in `auditor_app/` for reference.

---

## 2. Build `demo_app` (Standalone Crypto Demo)

No Maven required — compile and run with `javac` / `java` directly:

```bash
cd demo_app
javac CryptoDemo.java
java CryptoDemo
```

### Creating a jar

To package `CryptoDemo` as an executable jar:

```bash
cd demo_app
javac CryptoDemo.java
jar cfe CryptoDemo.jar CryptoDemo CryptoDemo.class
```

Run it with:

```bash
java -jar CryptoDemo.jar
```

### Testing the Auditor with the Demo

To run `CryptoDemo` under FIPS audit mode, first build `auditor_app`, then:

**Linux / macOS:**
```bash
cd demo_app
javac CryptoDemo.java

java \
  -Djava.security.properties==../auditor_app/security-audit.properties \
  -Dorg.bouncycastle.fips.approved_only=true \
  -Dfips.audit.log=fips-audit.log \
  -Dfips.audit.stack.depth=30 \
  -Xbootclasspath/a:../auditor_app/target/fips-audit-provider.jar:../auditor_app/target/dependency/bc-fips-2.0.0.jar \
  CryptoDemo
```

**Windows (cmd):**
```cmd
cd demo_app
javac CryptoDemo.java

java ^
  -Djava.security.properties==..\auditor_app\security-audit.properties ^
  -Dorg.bouncycastle.fips.approved_only=true ^
  -Dfips.audit.log=fips-audit.log ^
  -Dfips.audit.stack.depth=30 ^
  -Xbootclasspath/a:..\auditor_app\target\fips-audit-provider.jar;..\auditor_app\target\dependency\bc-fips-2.0.0.jar ^
  CryptoDemo
```

The audit log (`fips-audit.log`) will show every non-FIPS algorithm call with
the full caller stack trace.

---

## Project Structure

```
auditor_app/
  pom.xml                          Maven project → fips-audit-provider.jar
  security-audit.properties        JCA provider config (for deployment)
  src/main/java/.../
    FipsAuditProvider.java         JCA provider that intercepts crypto calls
    FipsPolicy.java                Configurable policy engine
  src/main/resources/
    fips-policy.properties         WEAK/DISALLOWED algorithm rules

demo_app/
  CryptoDemo.java                  Standalone test app (javac + java)
```
