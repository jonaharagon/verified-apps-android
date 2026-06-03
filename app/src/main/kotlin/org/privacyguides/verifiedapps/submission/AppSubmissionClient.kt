package org.privacyguides.verifiedapps.submission

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

object AppSubmissionClient {

    suspend fun submit(url: String, json: String, allowHttp: Boolean): Result<Unit> =
        withContext(Dispatchers.IO) {
            runCatching {
                validateUrl(url, allowHttp)
                val connection = (URL(url).openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    setRequestProperty("Content-Type", "application/json; charset=utf-8")
                    setRequestProperty("Accept", "application/json")
                    doOutput = true
                    connectTimeout = 15_000
                    readTimeout = 15_000
                }

                try {
                    connection.outputStream.use { output ->
                        output.write(json.toByteArray(Charsets.UTF_8))
                    }

                    val responseCode = connection.responseCode
                    if (responseCode !in 200..299) {
                        val errorBody = connection.errorStream?.bufferedReader()?.use { it.readText() }
                            ?.takeIf { it.isNotBlank() }
                        throw IOException(
                            errorBody ?: "Server returned HTTP $responseCode."
                        )
                    }
                } finally {
                    connection.disconnect()
                }
            }
        }

    private fun validateUrl(url: String, allowHttp: Boolean) {
        require(url.isNotBlank()) { "Submission URL is not configured." }
        val parsed = URL(url)
        require(parsed.protocol == "https" || (allowHttp && parsed.protocol == "http")) {
            "Submission URL must use HTTPS."
        }
    }
}
