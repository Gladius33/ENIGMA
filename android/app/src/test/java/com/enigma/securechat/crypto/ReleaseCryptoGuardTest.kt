package com.enigma.securechat.crypto

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertFalse
import org.junit.Test

class ReleaseCryptoGuardTest {
    @Test
    fun mainSourcesDoNotContainProvisionalCryptoEngine() {
        val mainSources = Path.of("src", "main", "java")
        val hits = Files.walk(mainSources).use { paths ->
            paths
                .filter { Files.isRegularFile(it) }
                .filter { it.toString().endsWith(".kt") }
                .filter { String(Files.readAllBytes(it)).contains("ProvisionalCryptoEngine") }
                .map { it.toString() }
                .toList()
        }

        assertFalse(
            "ProvisionalCryptoEngine must not appear in Android main sources: $hits",
            hits.isNotEmpty(),
        )
    }
}
