package uniffi.stoat_crypto

import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Test

/**
 * The AAR on an emulator (x86_64) or device: the packaged .so loads through
 * JNA, a DM and SAS between two machines in one process, the SQLite store in
 * app storage (CR-13). Run: `./gradlew connectedAndroidTest`.
 */
class BindingsDeviceTest {
    @Test
    fun dm() = runBlocking { Scenarios.dm() }

    @Test
    fun sas() = runBlocking { Scenarios.sas() }

    @Test
    fun sqliteStore() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val dir = File(context.cacheDir, "stoat-crypto-test")
        try {
            Scenarios.sqliteStore(dir)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun attachments() = Scenarios.attachments()
}
