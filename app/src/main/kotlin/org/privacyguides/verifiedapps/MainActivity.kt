package org.privacyguides.verifiedapps

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.core.content.IntentCompat
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.preferencesDataStore
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.flow.MutableSharedFlow
import org.privacyguides.verifiedapps.preferences.PreferencesViewModel
import org.privacyguides.verifiedapps.ui.VerifyAppViewModel
import org.privacyguides.verifiedapps.ui.theme.AppVerifierTheme

val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "preferences")

class MainActivity : ComponentActivity() {

    /**
     * APK URIs from SEND/VIEW intents delivered to the already-running activity
     * (launchMode="singleTop" routes them to [onNewIntent] instead of a new instance).
     * Buffered so a URI emitted just before the UI starts collecting is not dropped.
     */
    private val newApkUris = MutableSharedFlow<Uri>(extraBufferCapacity = 1)

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // Keep the activity's intent current so recreation (e.g. rotation) restores
        // this verification's context rather than the original launch intent's.
        setIntent(intent)
        intent.incomingApkUri()?.let(newApkUris::tryEmit)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)

        setContent {
            val verifyAppViewModel: VerifyAppViewModel = viewModel()

            val preferencesViewModel: PreferencesViewModel = viewModel(
                factory = PreferencesViewModel.PreferencesViewModelFactory(dataStore)
            )

            // Freeze the launch action at first composition: it selects the NavHost
            // start destination, which must stay stable across recompositions even
            // after onNewIntent calls setIntent. Later SEND/VIEW intents reach the
            // UI through newApkUris instead.
            val launchAction = rememberSaveable { intent.action ?: "" }
            val isActionSend = (launchAction == Intent.ACTION_SEND)
            val isActionView = (launchAction == Intent.ACTION_VIEW)

            // Process the launch intent's APK only once now.
            var intentHandled by rememberSaveable { mutableStateOf(false) }
            LaunchedEffect(Unit) {
                if (!intentHandled) {
                    intentHandled = true
                    val apkUri: Uri? = intent.incomingApkUri()
                    if (apkUri != null) {
                        verifyAppViewModel.setApkVerificationInfoAndInternalDatabaseStatusFromUri(
                            contentResolver,
                            apkUri,
                            packageManager,
                        )
                    }
                }
            }

            val preferencesLoaded by preferencesViewModel.preferencesLoaded.collectAsState()

            AppVerifierTheme(
                preferencesViewModel = preferencesViewModel
            ) {
                if (!preferencesLoaded) {
                    Box(
                        modifier = Modifier.fillMaxSize(),
                        contentAlignment = Alignment.Center,
                    ) {
                        CircularProgressIndicator()
                    }
                } else {
                    AppVerifierApp(
                        modifier = Modifier,
                        verifyAppViewModel = verifyAppViewModel,
                        preferencesViewModel = preferencesViewModel,
                        isActionSend = isActionSend,
                        isActionView = isActionView,
                        newApkUris = newApkUris,
                    )
                }
            }
        }
    }
}

/** The APK URI carried by a SEND/VIEW intent, or null for any other intent. */
private fun Intent.incomingApkUri(): Uri? = when (action) {
    Intent.ACTION_SEND -> IntentCompat.getParcelableExtra(this, Intent.EXTRA_STREAM, Uri::class.java)
    Intent.ACTION_VIEW -> data
    else -> null
}
