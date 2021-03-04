package net.mullvad.mullvadvpn.model

import android.os.Parcelable
import java.net.InetAddress
import java.util.ArrayList
import kotlinx.parcelize.Parcelize

@Parcelize
data class DnsOptions(val custom: Boolean, val addresses: ArrayList<InetAddress>) : Parcelable
