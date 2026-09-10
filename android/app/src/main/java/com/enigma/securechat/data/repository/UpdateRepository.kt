package com.enigma.securechat.data.repository

import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.network.ChatApiService
import com.enigma.securechat.network.toUserVisibleError
import com.enigma.securechat.network.dto.AndroidReleaseResponseDto
import java.io.File
import java.security.MessageDigest
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request

private val SHA256_HEX = Regex("^[0-9a-fA-F]{64}$")
private val SIGNATURE_PATTERN = Regex("^[A-Za-z0-9_+./=-]{16,}$")

enum class InstallSource {
    PLAY_STORE,
    FDROID,
    OFFICIAL_WEBSITE,
    GITHUB_BUILD,
    SIDELOAD,
    UNKNOWN,
}

data class AndroidUpdateStatus(
    val installSource: InstallSource,
    val release: AndroidReleaseInfo?,
    val signatureVerifierConfigured: Boolean,
)

data class AndroidReleaseInfo(
    val channel: String,
    val latestVersionName: String,
    val latestVersionCode: Long,
    val apkUrl: String,
    val sha256: String,
    val signature: String?,
    val mandatory: Boolean,
    val releaseNotesFr: String,
    val releaseNotesEn: String,
) {
    val hasSignature: Boolean = !signature.isNullOrBlank()
}

data class VerifiedApkDownload(
    val file: File,
    val sha256: String,
    val sizeBytes: Long,
    val signatureVerified: Boolean = false,
)

interface ApkDownloader {
    suspend fun download(url: String, destination: File): VerifiedApkDownload
}

interface ApkSignatureVerifier {
    val isConfigured: Boolean
    fun requireValidSignature(download: VerifiedApkDownload, signature: String?): VerifiedApkDownload
}

object NoopApkSignatureVerifier : ApkSignatureVerifier {
    override val isConfigured: Boolean = false

    override fun requireValidSignature(
        download: VerifiedApkDownload,
        signature: String?,
    ): VerifiedApkDownload {
        if (!signature.isNullOrBlank()) {
            download.file.delete()
            error("APK Ed25519 public key is not configured")
        }
        return download
    }
}

class JcaEd25519ApkSignatureVerifier private constructor(
    private val publicKeyDer: ByteArray?,
) : ApkSignatureVerifier {
    override val isConfigured: Boolean = publicKeyDer != null

    override fun requireValidSignature(
        download: VerifiedApkDownload,
        signature: String?,
    ): VerifiedApkDownload {
        if (publicKeyDer == null) return download
        val signatureBytes = signature
            ?.takeIf(String::isNotBlank)
            ?.let(::decodeBase64)
            ?: run {
                download.file.delete()
                error("APK Ed25519 signature is required")
            }
        val valid = runCatching {
            val key = KeyFactory
                .getInstance("Ed25519")
                .generatePublic(X509EncodedKeySpec(publicKeyDer))
            val verifier = Signature.getInstance("Ed25519")
            verifier.initVerify(key)
            download.file.inputStream().use { input ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val read = input.read(buffer)
                    if (read == -1) break
                    verifier.update(buffer, 0, read)
                }
            }
            verifier.verify(signatureBytes)
        }.getOrElse {
            download.file.delete()
            error("APK Ed25519 signature verification failed: ${it.message}")
        }
        if (!valid) {
            download.file.delete()
            error("APK Ed25519 signature mismatch")
        }
        return download.copy(signatureVerified = true)
    }

    companion object {
        fun fromBase64OrNoop(publicKeyBase64: String): ApkSignatureVerifier =
            publicKeyBase64
                .takeIf(String::isNotBlank)
                ?.let { JcaEd25519ApkSignatureVerifier(decodeBase64(it)) }
                ?: NoopApkSignatureVerifier
    }
}

class OkHttpApkDownloader(
    private val okHttpClient: OkHttpClient,
) : ApkDownloader {
    override suspend fun download(url: String, destination: File): VerifiedApkDownload =
        withContext(Dispatchers.IO) {
            require(url.startsWith("https://")) { "APK update URL must use HTTPS" }
            destination.parentFile?.mkdirs()
            val temp = File(destination.parentFile, "${destination.name}.tmp")
            val digest = MessageDigest.getInstance("SHA-256")
            var size = 0L
            val request = Request.Builder().url(url).get().build()
            okHttpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) error("APK download failed: HTTP ${response.code}")
                val body = requireNotNull(response.body) { "APK download response body is empty" }
                body.byteStream().use { input ->
                    temp.outputStream().use { output ->
                        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                        while (true) {
                            val read = input.read(buffer)
                            if (read == -1) break
                            digest.update(buffer, 0, read)
                            output.write(buffer, 0, read)
                            size += read
                        }
                    }
                }
            }
            if (destination.exists()) {
                destination.delete()
            }
            check(temp.renameTo(destination)) { "APK download could not be finalized" }
            VerifiedApkDownload(
                file = destination,
                sha256 = digest.digest().toHex(),
                sizeBytes = size,
            )
        }
}

class UpdateRepository(
    private val api: ChatApiService,
    private val installSourceProvider: () -> InstallSource = { InstallSource.UNKNOWN },
    private val apkDownloader: ApkDownloader? = null,
    private val apkSignatureVerifier: ApkSignatureVerifier = NoopApkSignatureVerifier,
    private val currentVersionCode: Long = 1,
    private val apkDestinationProvider: (AndroidReleaseInfo) -> File = {
        File("enigma-${it.latestVersionCode}.apk")
    },
) {
    suspend fun checkAndroidRelease(channel: String = "stable"): AppResult<AndroidUpdateStatus> =
        runCatching {
            val installSource = installSourceProvider()
            val release = if (installSource.allowsInternalUpdater()) {
                UpdateManifestValidator
                    .validate(api.androidRelease(channel))
                    .takeIf { it.latestVersionCode > currentVersionCode }
            } else {
                null
            }
            AndroidUpdateStatus(
                installSource = installSource,
                release = release,
                signatureVerifierConfigured = apkSignatureVerifier.isConfigured,
            )
        }.fold(
            onSuccess = { AppResult.Ok(it) },
            onFailure = {
                AppResult.Err(
                    it.toUserVisibleError("No valid sideload update manifest is configured for this relay"),
                )
            },
        )

    suspend fun downloadAndVerify(release: AndroidReleaseInfo): AppResult<VerifiedApkDownload> =
        runCatching {
            val downloader = requireNotNull(apkDownloader) { "APK downloader is not configured" }
            val downloaded = downloader.download(release.apkUrl, apkDestinationProvider(release))
            val shaVerified = UpdateDownloadVerifier.requireSha256(downloaded, release.sha256)
            apkSignatureVerifier.requireValidSignature(shaVerified, release.signature)
        }.fold(
            onSuccess = { AppResult.Ok(it) },
            onFailure = {
                AppResult.Err(it.toUserVisibleError("APK update download or verification failed"))
            },
        )
}

fun InstallSource.allowsInternalUpdater(): Boolean = when (this) {
    InstallSource.PLAY_STORE,
    InstallSource.FDROID -> false
    InstallSource.OFFICIAL_WEBSITE,
    InstallSource.GITHUB_BUILD -> true
    InstallSource.SIDELOAD,
    InstallSource.UNKNOWN -> true
}

internal object UpdateManifestValidator {
    fun validate(dto: AndroidReleaseResponseDto): AndroidReleaseInfo = with(dto) {
        require(platform == "android") { "Unsupported update platform" }
        require(channel.isNotBlank()) { "Missing update channel" }
        require(latestVersionName.isNotBlank()) { "Missing update version name" }
        require(latestVersionCode > 0) { "Invalid update version code" }
        require(apkUrl.startsWith("https://")) { "APK update URL must use HTTPS" }
        require(SHA256_HEX.matches(sha256)) { "Invalid APK SHA-256" }
        signature?.takeIf(String::isNotBlank)?.let {
            require(SIGNATURE_PATTERN.matches(it)) { "Invalid update signature" }
        }
        return AndroidReleaseInfo(
            channel = channel,
            latestVersionName = latestVersionName,
            latestVersionCode = latestVersionCode,
            apkUrl = apkUrl,
            sha256 = sha256.lowercase(),
            signature = signature?.takeIf(String::isNotBlank),
            mandatory = mandatory,
            releaseNotesFr = releaseNotes.fr,
            releaseNotesEn = releaseNotes.en,
        )
    }
}

internal object UpdateDownloadVerifier {
    fun requireSha256(download: VerifiedApkDownload, expectedSha256: String): VerifiedApkDownload {
        require(SHA256_HEX.matches(expectedSha256)) {
            "Invalid expected APK SHA-256"
        }
        if (!download.sha256.equals(expectedSha256, ignoreCase = true)) {
            download.file.delete()
            error("APK SHA-256 mismatch")
        }
        return download.copy(sha256 = download.sha256.lowercase())
    }
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

private fun decodeBase64(value: String): ByteArray =
    value.trim().let { trimmed ->
        runCatching { Base64.getDecoder().decode(trimmed) }
            .getOrElse { Base64.getUrlDecoder().decode(trimmed) }
    }
