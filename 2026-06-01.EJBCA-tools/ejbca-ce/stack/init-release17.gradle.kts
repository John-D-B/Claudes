// init-release17.gradle.kts — Gradle init script that pins every Java
// compilation in the build to release-17 bytecode + API surface.
//
// Why this exists: the upstream EJBCA-CE 9.3.7 container image runs on
// JDK 17, but our build host runs JDK 21+. Without --release 17, javac
// emits class files (version 65+) that WildFly's JVM (61) refuses to load
// with UnsupportedClassVersionError.
//
// Why an init script rather than editing build.gradle.kts: keeps our
// PR diff to upstream surgical — only the fix 26 / fix 27 code edits,
// no build-system changes. The init script lives in this workspace, not
// in the source tree.
//
// Applied automatically by ./Bin/3.3-build-local-image.sh via
//   gradle -I stack/init-release17.gradle.kts ...

allprojects {
    tasks.withType<JavaCompile>().configureEach {
        options.release.set(17)
    }
}
