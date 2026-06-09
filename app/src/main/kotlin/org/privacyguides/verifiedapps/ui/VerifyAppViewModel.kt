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
import org.privacyguides.verifiedapps.data.VerificationStatus
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
import java.security.MessageDigest
import java.util.UUID

class VerifyAppViewModel(application: Application) : AndroidViewModel(application) {

    private val _uiState = MutableStateFlow(VerifyAppUiState())
    val uiState: StateFlow<VerifyAppUiState> = _uiState.asStateFlow()

    fun setAppVerificationInfo(
        name: String,
        packageName: String,
        hashes: Hashes,
        internalDatabaseInfo: InternalDatabaseInfo,
        isSystemApp: Boolean = false,
    ) {
        _uiState.update {
            it.copy(
                name = name,
                packageName = packageName,
                hashes = hashes,
                internalDatabaseInfo = internalDatabaseInfo,
                isSystemApp = isSystemApp,
                // Clear any stale parse failure or verification status from a previous
                // verification; this ViewModel is activity-scoped and reused across
                // verifications.
                apkFailedToParse = false,
                verificationStatus = VerificationStatus.UNKNOWN,
            )
        }
    }

    fun setAppIcon(icon: Drawable) {
        _uiState.update { it.copy(icon = icon) }
    }

    fun verifyFromText(text: String) {
        _uiState.update { it.copy(verificationStatus = parseTextToVerificationStatus(text)) }
    }

    fun getVerificationInfoText(text: String): String {
        val trimmedText = text.trim().trim('"').lines().joinToString("") { it.trim().plus('\n') }

        return if (trimmedText.contains('"')) {
            trimmedText
                .lines()
                .dropLast(2)
                .joinToString("") {
                    it
                        .trim()
                        .replace(
                            ' ',
                            '\n'
                        )
                        .trim('"')
                        .plus('\n')
                }
        } else if (trimmedText.contains(' ')) {
            trimmedText
                .lines()
                .joinToString("") {
                    it
                        .trim()
                        .replace(
                            ' ',
                            '\n'
                        )
                        .plus('\n')
                }
        } else {
            trimmedText
        }
    }

    private fun parseTextToVerificationStatus(text: String): VerificationStatus {
        fun parseVerificationInfoTextToVerificationStatus(verificationInfoText: String): VerificationStatus {
            if (!uiState.value.hashes.hasMultipleSigners) {
                if (
                    (uiState.value.hashes.hashes.last() == verificationInfoText.lines()[0])
                    || (verificationInfoText.lines()[0].trim().iterator().run {
                        var convertedHash = ""
                        this.withIndex().forEach {
                            convertedHash += it.value
                            if (it.index % 2 != 0 && (it.index != verificationInfoText.lines()[0].trim().length.dec())) {
                                convertedHash += ":"
                            }
                        }
                        uiState.value.hashes.hashes.last() == convertedHash.uppercase()
                    })
                    || uiState.value.hashes.hashes.last() ==
                        verificationInfoText.lines()[0].trim() + ":" + verificationInfoText.lines()[1].trim()
                ) {
                    return VerificationStatus.PKG_NOT_GIVEN_BUT_SIG_HASH_MATCH
                } else if (verificationInfoText.lines()[0].length == 95) {
                    return VerificationStatus.PKG_NOT_GIVEN_AND_SIG_HASH_NOMATCH
                }
            } else if (uiState.value.hashes.hashes == verificationInfoText.lines()) {
                return VerificationStatus.PKG_NOT_GIVEN_BUT_SIG_HASH_MATCH
            }

            val isPackageNameMatch = verificationInfoText.lines()[0] == uiState.value.packageName
            val verificationStatus = if (uiState.value.hashes.hasMultipleSigners) {
                if (verificationInfoText.lines().drop(1) == uiState.value.hashes.hashes) {
                    VerificationStatus.MATCH
                } else {
                    VerificationStatus.NOMATCH
                }
            } else if (verificationInfoText.lines().drop(1).any {
                    uiState.value.hashes.hashes.last() == it
                }) {
                VerificationStatus.MATCH
            } else {
                VerificationStatus.NOMATCH
            }

            return if (isPackageNameMatch && (verificationStatus.ordinal == VerificationStatus.NOMATCH.ordinal)) {
                VerificationStatus.PKG_MATCH_BUT_SIG_HASH_NOMATCH
            } else if (!isPackageNameMatch && (verificationStatus.ordinal == VerificationStatus.MATCH.ordinal)) {
                VerificationStatus.PKG_NOMATCH_BUT_SIG_HASH_MATCH
            } else if (verificationStatus.ordinal == VerificationStatus.NOMATCH.ordinal) {
                VerificationStatus.NOMATCH
            } else if (verificationStatus.ordinal == VerificationStatus.MATCH.ordinal) {
                VerificationStatus.MATCH
            } else {
                TODO(
                    "This should never happen. If it does, then make sure you accounted for any new verification " +
                            "statuses that can happen in this function."
                )
            }
        }

        return parseVerificationInfoTextToVerificationStatus(getVerificationInfoText(text))
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
                val copied = contentResolver.openInputStream(uri)?.use { input ->
                    tempFile.outputStream().use { output -> input.copyTo(output) }
                    true
                } ?: false
                if (!copied) {
                    setApkFailedToParse(true)
                    return@launch
                }

                val packageInfo = packageManager.getPackageArchiveInfo(
                    tempFile.path,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                // No signing info means we cannot produce fingerprints to compare.
                if (packageInfo?.signingInfo == null) {
                    setApkFailedToParse(true)
                    return@launch
                }

                val applicationInfo = packageInfo.applicationInfo ?: ApplicationInfo()
                applicationInfo.sourceDir = tempFile.path
                applicationInfo.publicSourceDir = tempFile.path

                val packageName = packageInfo.packageName
                val hashes = getHashesFromPackageInfo(packageInfo)

                setAppVerificationInfo(
                    packageManager.getApplicationLabel(applicationInfo).toString(),
                    packageName,
                    hashes,
                    getInternalDatabaseInfoFromVerificationInfo(VerificationInfo(packageName, hashes)),
                    isSystemApp = packageManager.isInstalledSystemPackage(packageName),
                )
                setAppIcon(packageManager.getApplicationIcon(applicationInfo))
            } catch (_: IOException) {
                setApkFailedToParse(true)
            } finally {
                tempFile.delete()
            }
        }
    }
}

/** Format a digest as upper-case, colon-separated hex (the fingerprint form users compare). */
internal fun ByteArray.toUpperColonHex(): String =
    joinToString(":") { "%02x".format(it) }.uppercase()

private fun PackageManager.isInstalledSystemPackage(packageName: String): Boolean =
    getInstalledPackages(PackageManager.MATCH_SYSTEM_ONLY)
        .any { it.packageName == packageName }
