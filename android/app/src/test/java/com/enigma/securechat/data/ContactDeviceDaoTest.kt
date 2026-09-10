package com.enigma.securechat.data

import com.enigma.securechat.data.db.ContactDeviceDao
import com.enigma.securechat.data.db.ContactDeviceEntity
import com.enigma.securechat.data.db.ContactDeviceIdentityEventEntity
import com.enigma.securechat.data.db.ContactDeviceTrustState
import com.enigma.securechat.data.db.RemoteIdentityUpdate
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ContactDeviceDaoTest {
    @Test
    fun upsertRemoteIdentityPreservesVerificationWhenIdentityKeyIsStable() = runTest {
        val dao = InMemoryContactDeviceDao()
        dao.upsert(
            ContactDeviceEntity(
                deviceId = "device-1",
                contactUserId = "contact-1",
                identityKey = "identity-1",
                trustState = ContactDeviceTrustState.VERIFIED.name,
                verifiedSafetyNumber = "safety-1",
                verifiedAt = 123L,
            ),
        )

        dao.upsertRemoteIdentity(
            deviceId = "device-1",
            contactUserId = "contact-1",
            identityKey = "identity-1",
        )

        val stored = dao.findByDevice("device-1")
        assertEquals("safety-1", stored?.verifiedSafetyNumber)
        assertEquals(123L, stored?.verifiedAt)
        assertEquals(ContactDeviceTrustState.VERIFIED.name, stored?.trustState)
    }

    @Test
    fun upsertRemoteIdentityClearsVerificationWhenIdentityKeyChanges() = runTest {
        val dao = InMemoryContactDeviceDao()
        dao.upsert(
            ContactDeviceEntity(
                deviceId = "device-1",
                contactUserId = "contact-1",
                identityKey = "identity-1",
                trustState = ContactDeviceTrustState.VERIFIED.name,
                verifiedSafetyNumber = "safety-1",
                verifiedAt = 123L,
            ),
        )

        val update = dao.upsertRemoteIdentity(
            deviceId = "device-1",
            contactUserId = "contact-1",
            identityKey = "identity-2",
        )

        val stored = dao.findByDevice("device-1")
        assertEquals(RemoteIdentityUpdate.IDENTITY_CHANGED, update)
        assertEquals("identity-2", stored?.identityKey)
        assertEquals(ContactDeviceTrustState.CHANGED.name, stored?.trustState)
        assertNull(stored?.verifiedSafetyNumber)
        assertNull(stored?.verifiedAt)
        assertEquals(1, dao.identityEvents("device-1").size)
    }

        private class InMemoryContactDeviceDao : ContactDeviceDao {
        private val devices = linkedMapOf<String, ContactDeviceEntity>()
        private val events = mutableListOf<ContactDeviceIdentityEventEntity>()

        override suspend fun upsert(device: ContactDeviceEntity) {
            devices[device.deviceId] = device
        }

        override suspend fun findByDevice(deviceId: String): ContactDeviceEntity? =
            devices[deviceId]

        override suspend fun findByContact(contactUserId: String): List<ContactDeviceEntity> =
            devices.values.filter { it.contactUserId == contactUserId }

        override suspend fun markVerified(deviceId: String, safetyNumber: String, verifiedAt: Long) {
            devices[deviceId] = requireNotNull(devices[deviceId]).copy(
                verifiedSafetyNumber = safetyNumber,
                verifiedAt = verifiedAt,
                trustState = ContactDeviceTrustState.VERIFIED.name,
            )
        }

        override suspend fun insertIdentityEvent(event: ContactDeviceIdentityEventEntity) {
            events += event
        }

        override suspend fun identityEvents(deviceId: String): List<ContactDeviceIdentityEventEntity> =
            events.filter { it.deviceId == deviceId }
    }
}
