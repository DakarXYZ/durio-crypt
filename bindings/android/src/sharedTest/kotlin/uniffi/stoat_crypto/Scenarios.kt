package uniffi.stoat_crypto

import java.io.File
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail

/** A client as AN-21 runs one: request passes and mailbox passes */
class Device(val server: MiniServer, val user: String, val device: String, val machine: CryptoMachine) : AutoCloseable {
    private fun call(method: String, path: String, body: String?) = server.handle(user, device, method, path, body)

    suspend fun run(requests: List<OutgoingRequest>): Boolean {
        for (r in requests) {
            machine.markRequestSent(r.id, r.kind, call(r.method, r.path, r.body))
        }
        return requests.isNotEmpty()
    }

    suspend fun sync() {
        repeat(32) {
            val sent = run(machine.outgoingRequests())
            val result = machine.receiveToDevice(call("GET", "/e2ee/to_device?limit=100", null))
            if (result.ackIds.isNotEmpty()) {
                val ids = result.ackIds.joinToString(",") { "\"$it\"" }
                call("POST", "/e2ee/to_device/ack", "{\"ids\":[$ids]}")
                machine.markAckSent(result.ackIds)
            }
            machine.receiveOtkCounts(call("GET", "/e2ee/keys/count", null))
            if (!sent && result.fetched == 0u) return
        }
        fail("sync does not converge")
    }

    suspend fun send(channel: String, text: String): IncomingEncryptedMessage {
        while (run(machine.prepareSend(channel))) Unit
        val envelope = machine.encrypt(channel, textPayload(text, NONCE, 1uL))
        return server.post(channel, user, envelope)
    }

    override fun close() = machine.close()

    companion object {
        suspend fun open(server: MiniServer, user: String, device: String, store: StoreConfig = StoreConfig.Memory): Device {
            val machine = CryptoMachine.open(user, device, store)
            machine.setTiming(Timing(keyRequestDelayMs = 0uL, toDeviceRetryMs = 60_000uL, toDeviceRetryAttempts = 8u))
            return Device(server, user, device, machine).also { it.sync() }
        }
    }
}

const val NONCE = "AAAAAAAAAAAAAAAAAAAAAA"
val USER_A = "01KA".padEnd(26, 'A')
val USER_B = "01KB".padEnd(26, 'B')
val DEVICE_A = "01KDA1".padEnd(26, '1')
val DEVICE_B = "01KDB1".padEnd(26, '1')
val CHANNEL = "01KC".padEnd(26, 'C')

fun content(r: DecryptResult): String = when (r) {
    is DecryptResult.Decrypted -> Json.parse(r.message.payloadJson).jsonObject["content"]!!.jsonPrimitive.content
    is DecryptResult.Failed -> throw AssertionError("not decrypted: ${r.code}")
}

/** Scenarios shared by the JVM unit tests and the instrumented test */
object Scenarios {
    /** Two users in a DM: keys, Olm, Megolm through the bindings; batch with a newer envelope */
    suspend fun dm() {
        val server = MiniServer()
        Device.open(server, USER_A, DEVICE_A).use { a ->
            Device.open(server, USER_B, DEVICE_B).use { b ->
                for (d in listOf(a, b)) {
                    d.machine.setChannelMembers(CHANNEL, listOf(USER_A, USER_B), ChannelEncryptionSettings(null, null))
                }
                a.send(CHANNEL, "hello")
                b.sync()
                val first = server.messages(CHANNEL).single()
                val newer = first.copy(envelopeJson = first.envelopeJson.replace("\"v\":1", "\"v\":2"))
                val results = b.machine.decryptBatch(listOf(first, newer))
                assertEquals("hello", content(results[0]))
                val failed = results[1] as DecryptResult.Failed
                assertEquals(DecryptFailureKind.UpdateApp, failed.kind)
                val message = (results[0] as DecryptResult.Decrypted).message
                assertEquals(USER_A, message.senderUser)
                assertEquals(Verification.UNVERIFIED, message.verification)
                assertTrue(message.isClean)
                // the sender reads its own echo
                assertEquals("hello", content(a.machine.decrypt(first)))
            }
        }
    }

    /** SAS between two users: emoji equal on both sides, devices verified */
    suspend fun sas() {
        val server = MiniServer()
        Device.open(server, USER_A, DEVICE_A).use { a ->
            Device.open(server, USER_B, DEVICE_B).use { b ->
                for (d in listOf(a, b)) {
                    d.machine.setChannelMembers(CHANNEL, listOf(USER_A, USER_B), ChannelEncryptionSettings(null, null))
                    d.sync()
                }
                a.machine.requestVerification(USER_B, DEVICE_B).use { ha ->
                    assertEquals(SasState.Requested, ha.state())
                    a.sync(); b.sync()
                    b.machine.verification(ha.flowId())!!.use { hb ->
                        assertEquals(SasState.Incoming, hb.state())
                        hb.accept()
                        b.sync(); a.sync()
                        assertEquals(SasState.Ready, ha.state())
                        ha.start()
                        repeat(3) { a.sync(); b.sync() }
                        val ca = ha.state() as SasState.ShowCodes
                        val cb = hb.state() as SasState.ShowCodes
                        assertEquals(7, ca.emoji.size)
                        assertEquals(ca, cb)
                        val table = sasEmojiTable()
                        ca.emoji.forEach { assertEquals(table[it.index.toInt()], it) }
                        ha.confirm()
                        hb.confirm()
                        repeat(3) { a.sync(); b.sync() }
                        assertEquals(SasState.Done, ha.state())
                        assertEquals(SasState.Done, hb.state())
                        assertEquals(Trust.VERIFIED, a.machine.devices(USER_B).single().trust)
                    }
                }
            }
        }
    }

    /** Key export to a password-protected file and import on a new device (CR-21) */
    suspend fun keyExport() {
        val server = MiniServer()
        val deviceA2 = "01KDA2".padEnd(26, '2')
        Device.open(server, USER_A, DEVICE_A).use { a ->
            Device.open(server, USER_B, DEVICE_B).use { b ->
                for (d in listOf(a, b)) {
                    d.machine.setChannelMembers(CHANNEL, listOf(USER_A, USER_B), ChannelEncryptionSettings(null, null))
                }
                val sent = b.send(CHANNEL, "exported")
                a.sync()
                val passphrase = "pass phrase".toByteArray()
                val export = a.machine.exportRoomKeys(passphrase.copyOf(), emptyList())
                passphrase.fill(0)
                assertEquals(1u, export.sessions)
                assertTrue(export.data.startsWith("-----BEGIN MEGOLM SESSION DATA-----"))
                Device.open(server, USER_A, deviceA2).use { a2 ->
                    try {
                        a2.machine.importRoomKeys(export.data, "wrong".toByteArray())
                        fail("wrong passphrase accepted")
                    } catch (e: CryptoException.WrongPassphrase) {
                    }
                    val r = a2.machine.importRoomKeys(export.data, "pass phrase".toByteArray())
                    assertEquals(1u, r.imported)
                    assertEquals(CHANNEL, r.roomKeys.single().channelId)
                    val got = a2.machine.decrypt(sent)
                    assertEquals("exported", content(got))
                    assertEquals(Verification.UNAUTHENTICATED, (got as DecryptResult.Decrypted).message.verification)
                }
            }
        }
    }

    /** SQLite store: the key must be 32 bytes, one machine per store, destroy after close */
    suspend fun sqliteStore(dir: File) {
        val path = dir.absolutePath
        try {
            CryptoMachine.open(USER_A, DEVICE_A, StoreConfig.Sqlite(path, ByteArray(16)))
            fail("short key accepted")
        } catch (e: CryptoException.InvalidInput) {
        }
        val key = { ByteArray(32) { 7 } }
        val m = CryptoMachine.open(USER_A, DEVICE_A, StoreConfig.Sqlite(path, key()))
        try {
            CryptoMachine.open(USER_A, DEVICE_A, StoreConfig.Sqlite(path, key()))
            fail("store opened twice")
        } catch (e: CryptoException.StoreLocked) {
        }
        val identity = m.identityKeys()
        m.close()
        CryptoMachine.open(USER_A, DEVICE_A, StoreConfig.Sqlite(path, key())).use {
            assertEquals(identity, it.identityKeys())
        }
        destroyStore(StoreConfig.Sqlite(path, key()))
        assertTrue(!File(dir, "matrix-sdk-crypto.sqlite3").exists())
    }

    /** Chunked attachment: hash first, then decrypt; a swapped blob yields nothing */
    fun attachments() {
        val data = ByteArray(100_000) { (it % 251).toByte() }
        val blob = java.io.ByteArrayOutputStream()
        val file = AttachmentEncryptor().use { enc ->
            data.toList().chunked(attachmentChunkSize().toInt()).forEach { blob.write(enc.update(it.toByteArray())) }
            assertEquals(data.size.toULong(), enc.size())
            enc.finish()
        }
        val cipher = blob.toByteArray()
        assertNotEquals(data.toList(), cipher.toList())
        val plain = AttachmentVerifier(file).use { v ->
            v.update(cipher)
            v.finish().use { d -> d.update(cipher) }
        }
        assertArrayEquals(data, plain)
        cipher[0] = (cipher[0].toInt() xor 1).toByte()
        try {
            decryptAttachment(cipher, file)
            fail("swapped blob decrypted")
        } catch (e: CryptoException.AttachmentHashMismatch) {
        }
        val thumb = encryptAttachment("thumb".toByteArray())
        assertArrayEquals("thumb".toByteArray(), decryptAttachment(thumb.ciphertext, thumb.fileJson))
    }

    /** Shared vectors (fixtures/): recovery key classification and the SAS emoji table */
    fun fixtures(recoveryVectors: String, emojiTable: String) {
        val v = Json.parse(recoveryVectors).jsonObject
        v["valid"]!!.jsonArray.forEach {
            val key = it.jsonObject["recovery_key"]!!.jsonPrimitive.content
            assertEquals(RecoveryKeyCheck.VALID, recoveryKeyCheck(key.toByteArray()))
        }
        v["invalid"]!!.jsonArray.forEach {
            val o = it.jsonObject
            val expected = if (o["error"]!!.jsonPrimitive.content == "typo") RecoveryKeyCheck.TYPO else RecoveryKeyCheck.NOT_A_KEY
            assertEquals(expected, recoveryKeyCheck(o["input"]!!.jsonPrimitive.content.toByteArray()))
        }
        val table = sasEmojiTable()
        val emoji = Json.parse(emojiTable).jsonObject["emoji"]!!.jsonArray
        assertEquals(emoji.size, table.size)
        table.zip(emoji).forEach { (t, f) ->
            val o = f.jsonObject
            assertEquals(o["index"]!!.jsonPrimitive.content.toInt(), t.index.toInt())
            assertEquals(o["symbol"]!!.jsonPrimitive.content, t.symbol)
            assertEquals(o["description"]!!.jsonPrimitive.content, t.description)
        }
    }
}
