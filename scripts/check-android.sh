#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR/android"

if [[ -d /tmp/jdk-21 ]]; then
  export JAVA_HOME="${JAVA_HOME:-/tmp/jdk-21}"
elif [[ -d /usr/lib/jvm/java-21-openjdk-amd64 ]]; then
  export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"
fi
if [[ -d /tmp/android-sdk ]]; then
  export ANDROID_HOME="${ANDROID_HOME:-/tmp/android-sdk}"
  export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-/tmp/android-sdk}"
elif [[ -d "$HOME/Android/Sdk" ]]; then
  export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
  export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}"
fi
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-/tmp/gradle-home}"
if [[ "$GRADLE_USER_HOME" == /tmp/* && -d "$HOME/.gradle/caches" ]]; then
  export GRADLE_RO_DEP_CACHE="${GRADLE_RO_DEP_CACHE:-$HOME/.gradle/caches}"
fi

if [[ -x /tmp/gradle-8.7/bin/gradle ]]; then
  GRADLE_BIN="${GRADLE_BIN:-/tmp/gradle-8.7/bin/gradle}"
else
  GRADLE_BIN="${GRADLE_BIN:-./gradlew}"
fi

"$GRADLE_BIN" :app:assembleDebug :app:testDebugUnitTest :app:compileDebugAndroidTestKotlin
