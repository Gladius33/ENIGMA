package com.enigma.securechat.repository

import com.enigma.securechat.data.repository.UpdateManifestValidator
import com.enigma.securechat.data.repository.JcaEd25519ApkSignatureVerifier
import com.enigma.securechat.data.repository.InstallSource
import com.enigma.securechat.data.repository.NoopApkSignatureVerifier
import com.enigma.securechat.data.repository.UpdateDownloadVerifier
import com.enigma.securechat.data.repository.VerifiedApkDownload
import com.enigma.securechat.data.repository.allowsInternalUpdater
import com.enigma.securechat.network.dto.AndroidReleaseResponseDto
import com.enigma.securechat.network.dto.ReleaseNotesDto
import java.io.File
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateManifestValidatorTest {
    @Test
    fun acceptsHttpsManifestAndNormalizesSha256() {
        val release = UpdateManifestValidator.validate(
            manifest(sha256 = "A".repeat(64)),
        )

        assertEquals("stable", release.channel)
        assertEquals("a".repeat(64), release.sha256)
        assertTrue(release.hasSignature)
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsCleartextApkUrl() {
        UpdateManifestValidator.validate(
            manifest(apkUrl = "http://example.test/enigma.apk"),
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsInvalidSha256() {
        UpdateManifestValidator.validate(
            manifest(sha256 = "not-a-sha"),
        )
    }

    @Test
    fun acceptsDownloadedApkWhenSha256Matches() {
        val file = tempApk()
        val download = VerifiedApkDownload(
            file = file,
            sha256 = HELLO_SHA256.uppercase(),
            sizeBytes = 5,
        )

        val verified = UpdateDownloadVerifier.requireSha256(download, HELLO_SHA256)

        assertEquals(HELLO_SHA256, verified.sha256)
        assertFalse(verified.signatureVerified)
        assertTrue(file.exists())
    }

    @Test
    fun deletesDownloadedApkWhenSha256Mismatches() {
        val file = tempApk()
        val download = VerifiedApkDownload(
            file = file,
            sha256 = "0".repeat(64),
            sizeBytes = 5,
        )

        runCatching {
            UpdateDownloadVerifier.requireSha256(download, HELLO_SHA256)
        }

        assertFalse(file.exists())
    }

    @Test
    fun acceptsDownloadedApkWhenEd25519SignatureMatches() {
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val signature = Signature.getInstance("Ed25519").apply {
            initSign(keyPair.private)
            update(HELLO_BYTES)
        }.sign()
        val publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.public.encoded)
        val signatureBase64 = Base64.getEncoder().encodeToString(signature)
        val file = tempApk()
        val download = VerifiedApkDownload(
            file = file,
            sha256 = HELLO_SHA256,
            sizeBytes = 5,
        )

        val verified = JcaEd25519ApkSignatureVerifier
            .fromBase64OrNoop(publicKeyBase64)
            .requireValidSignature(download, signatureBase64)

        assertTrue(verified.signatureVerified)
        assertTrue(file.exists())
    }

    @Test
    fun deletesDownloadedApkWhenEd25519SignatureIsMissing() {
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.public.encoded)
        val file = tempApk()
        val download = VerifiedApkDownload(
            file = file,
            sha256 = HELLO_SHA256,
            sizeBytes = 5,
        )

        runCatching {
            JcaEd25519ApkSignatureVerifier
                .fromBase64OrNoop(publicKeyBase64)
                .requireValidSignature(download, null)
        }

        assertFalse(file.exists())
    }

    @Test
    fun deletesDownloadedApkWhenSignatureIsPresentButVerifierIsNotConfigured() {
        val file = tempApk()
        val download = VerifiedApkDownload(
            file = file,
            sha256 = HELLO_SHA256,
            sizeBytes = 5,
        )

        runCatching {
            NoopApkSignatureVerifier.requireValidSignature(download, "test-signature-0001")
        }

        assertFalse(file.exists())
    }

    @Test
    fun deletesDownloadedApkWhenEd25519SignatureMismatches() {
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val wrongKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val signature = Signature.getInstance("Ed25519").apply {
            initSign(wrongKeyPair.private)
            update(HELLO_BYTES)
        }.sign()
        val publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.public.encoded)
        val signatureBase64 = Base64.getEncoder().encodeToString(signature)
        val file = tempApk()
        val download = VerifiedApkDownload(
            file = file,
            sha256 = HELLO_SHA256,
            sizeBytes = 5,
        )

        runCatching {
            JcaEd25519ApkSignatureVerifier
                .fromBase64OrNoop(publicKeyBase64)
                .requireValidSignature(download, signatureBase64)
        }

        assertFalse(file.exists())
    }

    @Test
    fun internalUpdaterIsDisabledForStoreManagedInstalls() {
        assertFalse(InstallSource.PLAY_STORE.allowsInternalUpdater())
        assertFalse(InstallSource.FDROID.allowsInternalUpdater())
        assertTrue(InstallSource.OFFICIAL_WEBSITE.allowsInternalUpdater())
        assertTrue(InstallSource.GITHUB_BUILD.allowsInternalUpdater())
        assertTrue(InstallSource.SIDELOAD.allowsInternalUpdater())
        assertTrue(InstallSource.UNKNOWN.allowsInternalUpdater())
    }

    private fun manifest(
        apkUrl: String = "https://example.test/enigma.apk",
        sha256: String = "0123456789abcdef".repeat(4),
    ) = AndroidReleaseResponseDto(
        platform = "android",
        channel = "stable",
        latestVersionName = "1.0.1",
        latestVersionCode = 2,
        apkUrl = apkUrl,
        sha256 = sha256,
        signature = "test-signature-0001",
        mandatory = false,
        releaseNotes = ReleaseNotesDto(fr = "Notes FR", en = "Notes EN"),
    )

    private fun tempApk(): File =
        File.createTempFile("enigma-update-test", ".apk").also {
            it.writeText("hello")
            it.deleteOnExit()
        }

    private companion object {
        val HELLO_BYTES = "hello".toByteArray()
        const val HELLO_SHA256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    }
}
