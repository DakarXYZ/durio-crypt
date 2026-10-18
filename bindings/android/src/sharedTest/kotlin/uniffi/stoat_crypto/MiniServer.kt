package uniffi.stoat_crypto

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject

/**
 * The e2ee routes of contract v1 in memory, just enough for two
 * devices to exchange keys, messages and a SAS verification in one process
 * (the Rust fake server and the live backend are the real references).
 */
class MiniServer {
    private class Mail(val id: String, val recipient: String, val json: JsonObject)

    private val deviceKeys = mutableMapOf<String, MutableMap<String, JsonElement>>()
    private val otks = mutableMapOf<String, MutableMap<String, JsonElement>>()
    private val fallback = mutableMapOf<String, Pair<String, JsonElement>>()
    private val fallbackUsed = mutableMapOf<String, Boolean>()
    private val mailbox = mutableListOf<Mail>()
    private val messages = mutableMapOf<String, MutableList<IncomingEncryptedMessage>>()
    private var seq = 0

    private fun ulid(prefix: String): String {
        seq += 1
        return prefix + seq.toString().padStart(26 - prefix.length, '0')
    }

    @Synchronized
    fun handle(user: String, device: String, method: String, path: String, body: String?): String {
        val json = body?.takeIf { it.isNotEmpty() }?.let { Json.parse(it).jsonObject }
        val me = matrixId(user)
        return when {
            path == "/e2ee/keys/upload" -> {
                json?.get("device_keys")?.let { deviceKeys.getOrPut(me) { mutableMapOf() }[device] = it }
                json?.get("one_time_keys")?.jsonObject?.forEach { (id, key) ->
                    otks.getOrPut(device) { mutableMapOf() }[id] = key
                }
                json?.get("fallback_keys")?.jsonObject?.entries?.firstOrNull()?.let { (id, key) ->
                    fallback[device] = id to key
                    fallbackUsed[device] = false
                }
                counts(device).toString()
            }
            path == "/e2ee/keys/query" -> buildJsonObject {
                putJsonObject("device_keys") {
                    json!!["device_keys"]!!.jsonObject.keys.forEach { u ->
                        put(u, JsonObject(deviceKeys[u] ?: emptyMap()))
                    }
                }
                putJsonObject("failures") {}
            }.toString()
            path == "/e2ee/keys/claim" -> buildJsonObject {
                putJsonObject("one_time_keys") {
                    json!!["one_time_keys"]!!.jsonObject.forEach { (u, devices) ->
                        putJsonObject(u) {
                            devices.jsonObject.keys.forEach { d -> claim(d)?.let { (id, key) -> putJsonObject(d) { put(id, key) } } }
                        }
                    }
                }
                putJsonObject("failures") {}
            }.toString()
            path == "/e2ee/keys/count" -> counts(device).toString()
            path.startsWith("/e2ee/to_device/ack") -> {
                val ids = json!!["ids"]!!.jsonArray.map { it.jsonPrimitive.content }.toSet()
                mailbox.removeAll { it.recipient == device && it.id in ids }
                ""
            }
            path.startsWith("/e2ee/to_device?") -> buildJsonObject {
                put("messages", JsonArray(mailbox.filter { it.recipient == device }.take(100).map { it.json }))
            }.toString()
            path.startsWith("/e2ee/to_device/") && method == "PUT" -> {
                val type = json!!["type"]!!.jsonPrimitive.content
                json["messages"]!!.jsonObject.forEach { (u, devices) ->
                    devices.jsonObject.forEach { (d, content) ->
                        val targets = if (d == "*") deviceKeys[u]?.keys.orEmpty().filter { it != device } else listOf(d)
                        targets.forEach { t ->
                            val id = ulid("01KM")
                            mailbox += Mail(id, t, buildJsonObject {
                                put("id", id)
                                put("sender", me)
                                put("sender_device", device)
                                put("type", type)
                                put("content", content)
                            })
                        }
                    }
                }
                "{}"
            }
            else -> error("MiniServer: no route $method $path")
        }
    }

    private fun claim(device: String): Pair<String, JsonElement>? {
        otks[device]?.entries?.firstOrNull()?.let { (id, key) ->
            otks[device]!!.remove(id)
            return id to key
        }
        return fallback[device]?.also { fallbackUsed[device] = true }
    }

    private fun counts(device: String) = buildJsonObject {
        putJsonObject("one_time_key_counts") { put("signed_curve25519", otks[device]?.size ?: 0) }
        put("device_unused_fallback_key_types", buildJsonArray {
            if (fallbackUsed[device] == false) add(JsonPrimitive("signed_curve25519"))
        })
    }

    @Synchronized
    fun post(channel: String, author: String, envelopeJson: String): IncomingEncryptedMessage {
        val m = IncomingEncryptedMessage(
            messageId = ulid("01KX"),
            channelId = channel,
            author = author,
            envelopeJson = envelopeJson,
            replies = emptyList(),
            timestamp = 1_760_700_000_000uL,
        )
        messages.getOrPut(channel) { mutableListOf() } += m
        return m
    }

    @Synchronized
    fun messages(channel: String): List<IncomingEncryptedMessage> = messages[channel].orEmpty().toList()

    companion object {
        fun matrixId(user: String) = "@${user.lowercase()}:stoat.invalid"
    }
}

/** kotlinx.serialization without the compiler plugin */
object Json {
    fun parse(s: String): JsonElement = kotlinx.serialization.json.Json.parseToJsonElement(s)
}
