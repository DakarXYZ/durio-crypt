package uniffi.stoat_crypto

import java.io.File
import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The generated bindings against the host build of the library
 * (`jna.library.path` = build/host, see build.gradle.kts): the same Kotlin
 * the AAR ships, on the JVM, without an emulator (AN-34).
 */
class BindingsJvmTest {
    private fun fixture(rel: String) = File(System.getProperty("stoat.fixtures")!!, rel).readText()

    @Test
    fun version() = assertEquals(1u, payloadVersion())

    @Test
    fun dm() = runBlocking { Scenarios.dm() }

    @Test
    fun sas() = runBlocking { Scenarios.sas() }

    @Test
    fun keyExport() = runBlocking { Scenarios.keyExport() }

    @Test
    fun sqliteStore() = runBlocking {
        val dir = Files.createTempDirectory("stoat-crypto").toFile()
        try {
            Scenarios.sqliteStore(dir)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun attachments() = Scenarios.attachments()

    @Test
    fun fixtures() = Scenarios.fixtures(fixture("backup/recovery_key.vectors.json"), fixture("sas/emoji.json"))
}
