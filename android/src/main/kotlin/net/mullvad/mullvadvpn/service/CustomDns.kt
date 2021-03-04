package net.mullvad.mullvadvpn.service

import java.net.InetAddress
import java.util.ArrayList
import kotlin.properties.Delegates.observable
import net.mullvad.mullvadvpn.model.DnsOptions
import net.mullvad.talpid.util.EventNotifier

class CustomDns(val daemon: MullvadDaemon, val settingsListener: SettingsListener) {
    private var enabled by observable(false) { _, oldValue, newValue ->
        if (oldValue != newValue) {
            onEnabledChanged.notify(newValue)
        }
    }

    private var dnsServers by observable<ArrayList<InetAddress>>(ArrayList()) { _, _, servers ->
        onDnsServersChanged.notify(servers.toList())
    }

    val onEnabledChanged = EventNotifier(false)
    val onDnsServersChanged = EventNotifier<List<InetAddress>>(emptyList())

    init {
        settingsListener.dnsOptionsNotifier.subscribe(this) { maybeDnsOptions ->
            maybeDnsOptions?.let { dnsOptions ->
                enabled = dnsOptions.custom
                dnsServers = ArrayList(dnsOptions.addresses)
            }
        }
    }

    fun onDestroy() {
        settingsListener.dnsOptionsNotifier.unsubscribe(this)
    }

    fun enable() {
        synchronized(this) {
            changeDnsOptions(true, dnsServers)
        }
    }

    fun disable() {
        synchronized(this) {
            changeDnsOptions(false, dnsServers)
        }
    }

    fun addDnsServer(server: InetAddress): Boolean {
        synchronized(this) {
            if (!dnsServers.contains(server)) {
                dnsServers.add(server)
                changeDnsOptions(enabled, dnsServers)

                return true
            }
        }

        return false
    }

    fun replaceDnsServer(oldServer: InetAddress, newServer: InetAddress): Boolean {
        synchronized(this) {
            if (oldServer == newServer) {
                return true
            } else if (!dnsServers.contains(newServer)) {
                val index = dnsServers.indexOf(oldServer)

                if (index >= 0) {
                    dnsServers.removeAt(index)
                    dnsServers.add(index, newServer)
                    changeDnsOptions(enabled, dnsServers)

                    return true
                }
            }
        }

        return false
    }

    fun removeDnsServer(server: InetAddress) {
        synchronized(this) {
            if (dnsServers.remove(server)) {
                changeDnsOptions(enabled, dnsServers)
            }
        }
    }

    private fun changeDnsOptions(enable: Boolean, dnsServers: ArrayList<InetAddress>) {
        val options = DnsOptions(enable, dnsServers)

        daemon.setDnsOptions(options)
    }
}
