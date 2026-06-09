package org.privacyguides.verifiedapps.data

import android.graphics.drawable.Drawable
import androidx.compose.ui.graphics.Color
import org.privacyguides.verifiedapps.Source

data class VerifyAppUiState(
    val name: String = "",
    val packageName: String = "",
    val hashes: Hashes = Hashes(listOf(Source.NONE), listOf(""), false),
    val icon: Drawable? = null,
    val apkFailedToParse: Boolean = false,
    val isSystemApp: Boolean = false,
    val internalDatabaseInfo: InternalDatabaseInfo = InternalDatabaseInfo(
        InternalDatabaseStatus.NOT_FOUND,
        listOf(Source.NONE),
    ),
    val verificationStatus: VerificationStatus = VerificationStatus.UNKNOWN,
)

data class InternalDatabaseInfo(
    val internalDatabaseStatus: InternalDatabaseStatus,
    val sources: List<Source>,
)

enum class InternalDatabaseStatus {
    NOT_FOUND,
    MATCH,
    NOMATCH,
}

data class Hashes(
    val sources: List<Source>,
    val hashes: List<String>,
    val hasMultipleSigners: Boolean,
) {
    /**
     * Whether [other] describes the same signing configuration as this entry.
     * Fingerprint lists are compared as sets so order does not matter (e.g. certificate history).
     */
    fun matchesSigningFingerprints(other: Hashes): Boolean {
        if (hasMultipleSigners != other.hasMultipleSigners) {
            return false
        }
        return hashes.toSet() == other.hashes.toSet()
    }
}

data class VerificationInfo(val packageName: String, val hashes: Hashes)

enum class SimpleVerificationStatus(val color: Color) {
    UNKNOWN(Color.Gray),
    SUCCESS(Color.Green),
    WARNING(Color.Red.copy(red = 161f / 256f, green = 102f / 256f, blue = 14f / 256f)),
    FAILURE(Color.Red)
}

enum class VerificationStatus(val info: String, val simpleVerificationStatus: SimpleVerificationStatus) {
    UNKNOWN(
        "Since you haven't provided any verification info, I'm unable to determine the verification status",
        SimpleVerificationStatus.UNKNOWN,
    ),
    MATCH(
        "Both the package name and signing certificate hash match with the expected values",
        SimpleVerificationStatus.SUCCESS,
    ),
    NOMATCH(
        "Both the package name and the signing certificate hash DO NOT match with the expected values. Please make " +
                "sure you are verifying the correct app and check the formatting.",
        SimpleVerificationStatus.FAILURE,
    ),
    PKG_NOT_GIVEN_BUT_SIG_HASH_MATCH(
        "The package name was not given but the signing certificate hash matches",
        SimpleVerificationStatus.SUCCESS,
    ),
    PKG_NOMATCH_BUT_SIG_HASH_MATCH(
        "The package name does not match but the signing certificate hash matches. Please make sure you are verifying" +
                " the correct app.",
        SimpleVerificationStatus.WARNING,
    ),
    PKG_NOT_GIVEN_AND_SIG_HASH_NOMATCH(
        "The package name was not given and the signing certificate hash DOES NOT match. Please make sure you are " +
                "verifying the correct app.",
        SimpleVerificationStatus.FAILURE,
    ),
    PKG_MATCH_BUT_SIG_HASH_NOMATCH(
        "The package name matches but the signing certificate hash DOES NOT match. Be wary, the application might " +
                "be non-genuine.",
        SimpleVerificationStatus.FAILURE
    ),
}
