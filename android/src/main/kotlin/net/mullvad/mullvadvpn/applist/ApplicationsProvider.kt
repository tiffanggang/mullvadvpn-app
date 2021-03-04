package net.mullvad.mullvadvpn.applist

import android.Manifest
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager

class ApplicationsProvider(
    private val packageManager: PackageManager,
    private val thisPackageName: String
) {
    private val applicationFilterPredicate: (ApplicationInfo) -> Boolean = { appInfo ->
        hasInternetPermission(appInfo.packageName) &&
            isLaunchable(appInfo.packageName) &&
            !isSelfApplication(appInfo.packageName)
    }

    fun getAppsList(): List<AppInfo> {
        return packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
            .asSequence()
            .filter(applicationFilterPredicate)
            .map { info ->
                AppInfo(info.packageName, info.icon, info.loadLabel(packageManager).toString())
            }
            .toList()
    }

    private fun hasInternetPermission(packageName: String): Boolean {
        return PackageManager.PERMISSION_GRANTED ==
            packageManager.checkPermission(Manifest.permission.INTERNET, packageName)
    }

    private fun isSelfApplication(packageName: String): Boolean {
        return packageName == thisPackageName
    }

    private fun isLaunchable(packageName: String): Boolean {
        return packageManager.getLaunchIntentForPackage(packageName) != null
    }
}
