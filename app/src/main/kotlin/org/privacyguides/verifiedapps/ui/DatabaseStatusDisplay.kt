package org.privacyguides.verifiedapps.ui

import androidx.annotation.StringRes
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.HelpOutline
import androidx.compose.material3.Icon
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import org.privacyguides.verifiedapps.R
import org.privacyguides.verifiedapps.data.InternalDatabaseStatus
import org.privacyguides.verifiedapps.ui.theme.MismatchRed
import org.privacyguides.verifiedapps.ui.theme.UnknownGray
import org.privacyguides.verifiedapps.ui.theme.VerifiedGreen

@StringRes
fun InternalDatabaseStatus.labelRes(): Int = when (this) {
    InternalDatabaseStatus.MATCH -> R.string.app_list_status_verified
    InternalDatabaseStatus.NOMATCH -> R.string.app_list_status_mismatch
    InternalDatabaseStatus.NOT_FOUND -> R.string.app_list_status_unknown
}

fun InternalDatabaseStatus.statusColor(): Color = when (this) {
    InternalDatabaseStatus.MATCH -> VerifiedGreen
    InternalDatabaseStatus.NOMATCH -> MismatchRed
    InternalDatabaseStatus.NOT_FOUND -> UnknownGray
}

fun InternalDatabaseStatus.statusIcon(): ImageVector = when (this) {
    InternalDatabaseStatus.MATCH -> Icons.Default.CheckCircle
    InternalDatabaseStatus.NOMATCH -> Icons.Default.Error
    InternalDatabaseStatus.NOT_FOUND -> Icons.Default.HelpOutline
}

@Composable
fun DatabaseStatusIcon(
    status: InternalDatabaseStatus,
    modifier: Modifier = Modifier,
) {
    Icon(
        imageVector = status.statusIcon(),
        contentDescription = stringResource(status.labelRes()),
        tint = status.statusColor(),
        modifier = modifier,
    )
}
