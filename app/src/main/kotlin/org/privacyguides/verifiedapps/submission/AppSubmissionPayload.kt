package org.privacyguides.verifiedapps.submission

import org.privacyguides.verifiedapps.data.Hashes
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant

object AppSubmissionPayload {

    fun toJson(
        packageName: String,
        appLabel: String,
        hashes: Hashes,
        applicationId: String,
        versionName: String,
        versionCode: Int,
    ): String {
        val signingCertificateSha256 = JSONArray()
        hashes.hashes.forEach { signingCertificateSha256.put(it) }

        val client = JSONObject()
            .put("applicationId", applicationId)
            .put("versionName", versionName)
            .put("versionCode", versionCode)

        return JSONObject()
            .put("packageName", packageName)
            .put("appLabel", appLabel)
            .put("hasMultipleSigners", hashes.hasMultipleSigners)
            .put("signingCertificateSha256", signingCertificateSha256)
            .put("submittedAt", Instant.now().toString())
            .put("client", client)
            .toString()
    }
}
