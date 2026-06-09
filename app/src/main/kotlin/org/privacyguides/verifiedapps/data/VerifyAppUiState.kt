package org.privacyguides.verifiedapps.data

import android.graphics.drawable.Drawable
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
        // Compare as a case-insensitive set. SHA-256 hex fingerprints are
        // case-insensitive by definition, so canonicalizing here keeps a casing
        // drift in the bundled database from ever producing a false mismatch. It
        // can never produce a false match: this is still exact per-fingerprint
        // hex equality, just normalized.
        return hashes.mapTo(HashSet()) { it.uppercase() } ==
            other.hashes.mapTo(HashSet()) { it.uppercase() }
    }
}

data class VerificationInfo(val packageName: String, val hashes: Hashes)
