package com.enigma.securechat.data

import com.enigma.securechat.data.db.ContactEntity
import com.enigma.securechat.data.mapper.toDomain
import com.enigma.securechat.data.mapper.toEntity
import com.enigma.securechat.data.mapper.toRemoteBundle
import com.enigma.securechat.domain.model.Contact
import com.enigma.securechat.network.dto.DeviceKeyBundleDto
import com.enigma.securechat.network.dto.KyberPreKeyDto
import com.enigma.securechat.network.dto.OneTimePreKeyDto
import com.enigma.securechat.network.dto.SignedPreKeyDto
import org.junit.Assert.assertEquals
import org.junit.Test

class DomainMappersTest {
    @Test
    fun contactRoundTripPreservesFields() {
        val contact = Contact(
            userId = "user-1",
            publicId = "alice",
            displayName = "Alice",
        )

        val entity = contact.toEntity()
        val mapped = entity.toDomain()

        assertEquals(ContactEntity("user-1", "alice", "Alice"), entity)
        assertEquals(contact, mapped)
    }

    @Test
    fun keyBundleMapperPreservesLibsignalMetadata() {
        val dto = DeviceKeyBundleDto(
            deviceId = "device-1",
            identityKey = "identity-key",
            registrationId = 12345,
            protocolDeviceId = 1,
            signedPreKey = SignedPreKeyDto(
                keyId = 7,
                publicKey = "signed-prekey",
                signature = "signed-signature",
            ),
            kyberPreKey = KyberPreKeyDto(
                keyId = 8,
                publicKey = "kyber-prekey",
                signature = "kyber-signature",
            ),
            oneTimePreKey = OneTimePreKeyDto(
                keyId = 9,
                publicKey = "one-time-prekey",
            ),
        )

        val mapped = dto.toRemoteBundle()

        assertEquals("device-1", mapped.deviceId)
        assertEquals("identity-key", mapped.identityKey)
        assertEquals(12345, mapped.registrationId)
        assertEquals(1, mapped.protocolDeviceId)
        assertEquals(7L, mapped.signedPreKey.keyId)
        assertEquals("signed-prekey", mapped.signedPreKey.publicKey)
        assertEquals("signed-signature", mapped.signedPreKey.signature)
        assertEquals(8L, mapped.kyberPreKey?.keyId)
        assertEquals("kyber-prekey", mapped.kyberPreKey?.publicKey)
        assertEquals("kyber-signature", mapped.kyberPreKey?.signature)
        assertEquals(9L, mapped.oneTimePreKey?.keyId)
        assertEquals("one-time-prekey", mapped.oneTimePreKey?.publicKey)
    }
}
