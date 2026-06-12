package org.privacyguides.verifiedapps.ui

import android.app.Application
import android.content.ContentResolver
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import org.privacyguides.verifiedapps.Source
import org.privacyguides.verifiedapps.data.Hashes
import org.privacyguides.verifiedapps.data.InternalDatabaseInfo
import org.privacyguides.verifiedapps.data.VerificationInfo
import org.privacyguides.verifiedapps.data.VerifyAppUiState
import org.privacyguides.verifiedapps.internalDatabaseInfoFor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong

class VerifyAppViewModel(application: Application) : AndroidViewModel(application) {

    private val _uiState = MutableStateFlow(VerifyAppUiState())
    val uiState: StateFlow<VerifyAppUiState> = _uiState.asStateFlow()

    /**
     * Identifies the most recently requested verification. APK parses run
     * asynchronously and a new verification can be requested while one is still in
     * flight (e.g. a second APK shared to the running activity), so each parse
     * applies its result only if it is still the latest request — a slow, superseded
     * parse must never overwrite a newer verdict with an older APK's.
     */
    private val verificationGeneration = AtomicLong(0)

    fun setAppVerificationInfo(
        name: String,
        packageName: String,
        hashes: Hashes,
        internalDatabaseInfo: InternalDatabaseInfo,
        isSystemApp: Boolean = false,
    ) {
        // This synchronous verification (e.g. selecting an app from the list)
        // supersedes any APK parse still in flight.
        verificationGeneration.incrementAndGet()
        _uiState.update {
            it.copy(
                name = name,
                packageName = packageName,
                hashes = hashes,
                internalDatabaseInfo = internalDatabaseInfo,
                isSystemApp = isSystemApp,
                // Clear any stale parse failure from a previous verification; this
                // ViewModel is activity-scoped and reused across verifications.
                apkFailedToParse = false,
            )
        }
    }

    fun setAppIcon(icon: Drawable) {
        _uiState.update { it.copy(icon = icon) }
    }

    fun getHashesFromPackageInfo(packageInfo: PackageInfo): Hashes {
        val signingInfo = packageInfo.signingInfo
            ?: throw IllegalStateException(
                "PackageInfo.signingInfo is null for package ${packageInfo.packageName}"
            )
        val hasMultipleSigners = signingInfo.hasMultipleSigners()

        // For multiple signers, every current signer must be present; otherwise the
        // full single-key rotation history is what identifies the app.
        val signatures = if (hasMultipleSigners) {
            signingInfo.apkContentsSigners
        } else {
            signingInfo.signingCertificateHistory
        }.map { signature ->
            MessageDigest.getInstance("SHA-256").digest(signature.toByteArray()).toUpperColonHex()
        }

        return Hashes(listOf(Source.NONE), signatures, hasMultipleSigners)
    }

    fun setApkFailedToParse(b: Boolean) {
        _uiState.update { it.copy(apkFailedToParse = b) }
    }

    fun getInternalDatabaseInfoFromVerificationInfo(
        verificationInfo: VerificationInfo,
    ): InternalDatabaseInfo = internalDatabaseInfoFor(verificationInfo)

    fun setApkVerificationInfoAndInternalDatabaseStatusFromUri(
        contentResolver: ContentResolver,
        uri: Uri,
        packageManager: PackageManager,
    ) {
        // Clear the previous verdict before anything else: a second APK can arrive
        // while the screen still shows the last APK's result, and that stale verdict
        // must never be readable as the new APK's.
        val generation = verificationGeneration.incrementAndGet()
        _uiState.value = VerifyAppUiState()
        // Copying and parsing an APK (potentially hundreds of MB) must never run on
        // the main thread. State updates flow back through StateFlow, which Compose
        // collects on the main thread.
        viewModelScope.launch(Dispatchers.IO) {
            // A unique cache file per verification avoids concurrent overwrite/delete races.
            val tempFile = File(
                getApplication<Application>().cacheDir,
                "pending-verification-${UUID.randomUUID()}.apk"
            )
            try {
                // The URI comes from another app via the exported SEND/VIEW intents, so
                // the stream behind it is untrusted: copy it with a hard size ceiling so a
                // malicious or unbounded content provider cannot fill the device's storage.
                val copied = contentResolver.openInputStream(uri)?.use { input ->
                    tempFile.outputStream().use { output ->
                        input.copyBounded(output, MAX_APK_BYTES)
                    }
                } ?: false
                if (!copied) {
                    ifCurrentVerification(generation) { setApkFailedToParse(true) }
                    return@launch
                }

                val packageInfo = packageManager.getPackageArchiveInfo(
                    tempFile.path,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                // No signing info means we cannot produce fingerprints to compare.
                if (packageInfo?.signingInfo == null) {
                    ifCurrentVerification(generation) { setApkFailedToParse(true) }
                    return@launch
                }

                val applicationInfo = packageInfo.applicationInfo ?: ApplicationInfo()
                applicationInfo.sourceDir = tempFile.path
                applicationInfo.publicSourceDir = tempFile.path

                val packageName = packageInfo.packageName
                val hashes = getHashesFromPackageInfo(packageInfo)

                ifCurrentVerification(generation) {
                    setAppVerificationInfo(
                        packageManager.getApplicationLabel(applicationInfo).toString(),
                        packageName,
                        hashes,
                        getInternalDatabaseInfoFromVerificationInfo(VerificationInfo(packageName, hashes)),
                        isSystemApp = packageManager.isInstalledSystemPackage(packageName),
                    )
                    setAppIcon(packageManager.getApplicationIcon(applicationInfo))
                }
            } catch (_: IOException) {
                ifCurrentVerification(generation) { setApkFailedToParse(true) }
            } finally {
                tempFile.delete()
            }
        }
    }

    /** Run [block] only if [generation] is still the most recently requested verification. */
    private inline fun ifCurrentVerification(generation: Long, block: () -> Unit) {
        if (verificationGeneration.get() == generation) {
            block()
        }
    }
}

/**
 * Upper bound on the bytes copied from an incoming APK URI. Comfortably larger than any
 * real monolithic APK a user would verify, but finite so an unbounded/hostile stream from
 * another app cannot exhaust storage. Exceeding it is surfaced as a parse failure.
 */
private const val MAX_APK_BYTES = 4L * 1024 * 1024 * 1024 // 4 GiB

/**
 * Copy this stream to [output], stopping and returning false if more than [maxBytes] would
 * be written. Returns true once the source is fully copied within the limit.
 */
private fun InputStream.copyBounded(output: OutputStream, maxBytes: Long): Boolean {
    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
    var total = 0L
    while (true) {
        val read = read(buffer)
        if (read < 0) return true
        total += read
        if (total > maxBytes) return false
        output.write(buffer, 0, read)
    }
}

/** Format a digest as upper-case, colon-separated hex (the fingerprint form users compare). */
internal fun ByteArray.toUpperColonHex(): String =
    joinToString(":") { "%02x".format(it) }.uppercase()

private fun PackageManager.isInstalledSystemPackage(packageName: String): Boolean =
    getInstalledPackages(PackageManager.MATCH_SYSTEM_ONLY)
        .any { it.packageName == packageName }
