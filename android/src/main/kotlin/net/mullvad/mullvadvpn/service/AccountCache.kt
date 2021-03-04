package net.mullvad.mullvadvpn.service

import kotlinx.coroutines.delay
import net.mullvad.mullvadvpn.model.GetAccountDataResult
import net.mullvad.mullvadvpn.service.endpoint.SettingsListener
import net.mullvad.mullvadvpn.util.ExponentialBackoff
import net.mullvad.mullvadvpn.util.JobTracker
import net.mullvad.talpid.util.EventNotifier
import org.joda.time.DateTime
import org.joda.time.format.DateTimeFormat

class AccountCache(val daemon: MullvadDaemon, val settingsListener: SettingsListener) {
    companion object {
        public val EXPIRY_FORMAT = DateTimeFormat.forPattern("YYYY-MM-dd HH:mm:ss z")

        // Number of retry attempts to check for a changed expiry before giving up.
        // Current value will force the cache to keep fetching for about four minutes or until a new
        // expiry value is received.
        // This is only used if the expiry was invalidated and fetching a new expiry returns the
        // same value as before the invalidation.
        private const val MAX_INVALIDATED_RETRIES = 7
    }

    val onAccountNumberChange = EventNotifier<String?>(null)
    val onAccountExpiryChange = EventNotifier<DateTime?>(null)
    val onAccountHistoryChange = EventNotifier<ArrayList<String>>(ArrayList())

    var newlyCreatedAccount = false
        private set

    private val jobTracker = JobTracker()

    private var accountNumber by onAccountNumberChange.notifiable()
    private var accountExpiry by onAccountExpiryChange.notifiable()
    private var accountHistory by onAccountHistoryChange.notifiable()

    private var createdAccountExpiry: DateTime? = null
    private var oldAccountExpiry: DateTime? = null

    init {
        settingsListener.accountNumberNotifier.subscribe(this) { accountNumber ->
            handleNewAccountNumber(accountNumber)
        }
    }

    fun createNewAccount(): String? {
        newlyCreatedAccount = true
        createdAccountExpiry = null

        return daemon.createNewAccount()
    }

    fun login(account: String) {
        if (account != accountNumber) {
            markAccountAsNotNew()
            daemon.setAccount(account)
        }
    }

    fun fetchAccountExpiry() {
        synchronized(this) {
            accountNumber?.let { account ->
                jobTracker.newBackgroundJob("fetch") {
                    val delays = ExponentialBackoff().apply {
                        cap = 2 /* h */ * 60 /* min */ * 60 /* s */ * 1000 /* ms */
                    }

                    do {
                        val result = daemon.getAccountData(account)

                        if (result is GetAccountDataResult.Ok) {
                            val expiry = result.accountData.expiry
                            val retryAttempt = delays.iteration

                            if (handleNewExpiry(account, expiry, retryAttempt)) {
                                break
                            }
                        } else if (result is GetAccountDataResult.InvalidAccount) {
                            break
                        }

                        delay(delays.next())
                    } while (onAccountExpiryChange.hasListeners())
                }
            }
        }
    }

    fun invalidateAccountExpiry(accountExpiryToInvalidate: DateTime) {
        synchronized(this) {
            if (accountExpiry == accountExpiryToInvalidate) {
                oldAccountExpiry = accountExpiryToInvalidate
                fetchAccountExpiry()
            }
        }
    }

    fun removeAccountFromHistory(accountToken: String) {
        jobTracker.newBackgroundJob("removeAccountFromHistory $accountToken") {
            daemon.removeAccountFromHistory(accountToken)
            fetchAccountHistory()
        }
    }

    fun onDestroy() {
        settingsListener.accountNumberNotifier.unsubscribe(this)
        jobTracker.cancelAllJobs()
    }

    private fun fetchAccountHistory() {
        jobTracker.newBackgroundJob("fetchHistory") {
            daemon.getAccountHistory()?.let { history ->
                accountHistory = history
            }
        }
    }

    private fun markAccountAsNotNew() {
        newlyCreatedAccount = false
        createdAccountExpiry = null
    }

    private fun handleNewAccountNumber(newAccountNumber: String?) {
        synchronized(this) {
            accountExpiry = null
            accountNumber = newAccountNumber

            fetchAccountExpiry()
            fetchAccountHistory()
        }
    }

    private fun handleNewExpiry(
        accountNumberUsedForFetch: String,
        expiryString: String,
        retryAttempt: Int
    ): Boolean {
        synchronized(this) {
            if (accountNumber !== accountNumberUsedForFetch) {
                return true
            }

            val newAccountExpiry = DateTime.parse(expiryString, EXPIRY_FORMAT)

            if (newAccountExpiry != oldAccountExpiry || retryAttempt >= MAX_INVALIDATED_RETRIES) {
                accountExpiry = newAccountExpiry
                oldAccountExpiry = null

                if (accountExpiry != null && newlyCreatedAccount) {
                    if (createdAccountExpiry == null) {
                        createdAccountExpiry = accountExpiry
                    } else if (accountExpiry != createdAccountExpiry) {
                        markAccountAsNotNew()
                    }
                }

                return true
            }

            return false
        }
    }
}
