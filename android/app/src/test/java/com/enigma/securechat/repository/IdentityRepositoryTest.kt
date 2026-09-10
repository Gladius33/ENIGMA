package com.enigma.securechat.repository

import com.enigma.securechat.crypto.CryptoEngine
import com.enigma.securechat.crypto.LocalIdentity
import com.enigma.securechat.crypto.PreKeyUploadBundle
import com.enigma.securechat.crypto.RemoteDeviceBundle
import com.enigma.securechat.crypto.RemoteDeviceRef
import com.enigma.securechat.data.repository.AccountDataPurger
import com.enigma.securechat.data.repository.IdentityRepository
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.domain.model.UserSession
import com.enigma.securechat.network.ChatApiService
import com.enigma.securechat.network.dto.*
import com.enigma.securechat.storage.DevicePersistence
import com.enigma.securechat.storage.SessionPersistence
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IdentityRepositoryTest {
    @Test
    fun deleteMePurgesLocalAccountDataAfterServerDeletion() = runTest {
        val api = FakeApi()
        val purger = FakeAccountDataPurger()
        val repository = IdentityRepository(api, FakeCryptoEngine(), FakeDeviceStore(), FakeSessionStore(), purger)
        val result = repository.deleteMe()
        assertTrue(result is AppResult.Ok)
        assertTrue(api.deleted)
        assertTrue(purger.purged)
    }

    @Test
    fun deleteMeDoesNotPurgeLocalAccountDataWhenServerDeletionFails() = runTest {
        val api = FakeApi(deleteFails = true)
        val purger = FakeAccountDataPurger()
        val repository = IdentityRepository(api, FakeCryptoEngine(), FakeDeviceStore(), FakeSessionStore(), purger)
        val result = repository.deleteMe()
        assertTrue(result is AppResult.Err)
        assertFalse(purger.purged)
    }

    private class FakeAccountDataPurger : AccountDataPurger {
        var purged = false
        override suspend fun purgeAccountData() { purged = true }
    }

    private class FakeDeviceStore : DevicePersistence {
        override suspend fun saveDeviceId(deviceId: String) = Unit
        override suspend fun deviceId(): String? = null
        override suspend fun clearDeviceId() = Unit
    }

    private class FakeSessionStore : SessionPersistence {
        override suspend fun saveSession(value: UserSession) = Unit
        override suspend fun clearSession() = Unit
    }

    private class FakeCryptoEngine : CryptoEngine {
        override suspend fun ensureIdentity(): LocalIdentity = unsupported()
        override suspend fun createPreKeyUpload(deviceId: String, oneTimePreKeyCount: Int): PreKeyUploadBundle = unsupported()
        override suspend fun hasSession(recipient: RemoteDeviceRef): Boolean = unsupported()
        override suspend fun ensureSession(recipient: RemoteDeviceBundle): Unit = unsupported()
        override suspend fun encryptText(plaintext: String, recipient: RemoteDeviceRef): String = unsupported()
        override suspend fun encryptText(plaintext: String, recipient: RemoteDeviceBundle): String = unsupported()
        override suspend fun decryptText(ciphertext: String): String = unsupported()
    }

    private class FakeApi(private val deleteFails: Boolean = false) : ChatApiService {
        var deleted = false
        override suspend fun deleteIdentity(): DeleteIdentityResponseDto {
            if (deleteFails) error("server rejected deletion")
            deleted = true
            return DeleteIdentityResponseDto("deleted", "alice", true)
        }
        override suspend fun health(): HealthResponseDto = unsupported()
        override suspend fun version(): VersionResponseDto = unsupported()
        override suspend fun register(body: AuthRequestDto): AuthResponseDto = unsupported()
        override suspend fun login(body: AuthRequestDto): AuthResponseDto = unsupported()
        override suspend fun registerDevice(body: DeviceRegisterRequestDto): DeviceRegisterResponseDto = unsupported()
        override suspend fun updateFcmToken(body: FcmTokenRequestDto): StatusResponseDto = unsupported()
        override suspend fun devices(): DevicesResponseDto = unsupported()
        override suspend fun deleteDevice(deviceId: String): StatusResponseDto = unsupported()
        override suspend fun uploadKeys(body: UploadKeysRequestDto): UploadKeysResponseDto = unsupported()
        override suspend fun getKeys(userId: String): KeyBundleResponseDto = unsupported()
        override suspend fun discoverKeys(userId: String): KeyBundleResponseDto = unsupported()
        override suspend fun claimPreKey(userId: String, deviceId: String): ClaimPreKeyResponseDto = unsupported()
        override suspend fun keyStatus(): KeyStatusResponseDto = unsupported()
        override suspend fun resolveUser(publicId: String): ResolveUserResponseDto = unsupported()
        override suspend fun checkIdentity(handle: String): IdentityCheckResponseDto = unsupported()
        override suspend fun createIdentity(body: CreateIdentityRequestDto): IdentityResponseDto = unsupported()
        override suspend fun recoverStart(body: RecoverStartRequestDto): RecoverStartResponseDto = unsupported()
        override suspend fun recoverComplete(body: RecoverCompleteRequestDto): IdentityResponseDto = unsupported()
        override suspend fun addContact(body: AddContactRequestDto): ContactDto = unsupported()
        override suspend fun contacts(): ContactsResponseDto = unsupported()
        override suspend fun deleteContact(contactUserId: String): StatusResponseDto = unsupported()
        override suspend fun bubbles(): BubblesResponseDto = unsupported()
        override suspend fun createBubble(body: CreateBubbleRequestDto): BubbleDto = unsupported()
        override suspend fun bubble(bubbleId: String): BubbleDto = unsupported()
        override suspend fun bubbleMembers(bubbleId: String): BubbleMembersResponseDto = unsupported()
        override suspend fun bubbleRelays(bubbleId: String): BubbleRelaysResponseDto = unsupported()
        override suspend fun addBubbleRelay(bubbleId: String, body: AddBubbleRelayRequestDto): BubbleRelayDto = unsupported()
        override suspend fun relays(): RelaysResponseDto = unsupported()
        override suspend fun createCustomRelay(body: CreateCustomRelayRequestDto): RelayDto = unsupported()
        override suspend fun officialRelayDescriptor(): RelayDto = unsupported()
        override suspend fun sendMessage(body: SendMessageRequestDto): SendMessageResponseDto = unsupported()
        override suspend fun pendingMessages(deviceId: String): PendingMessagesResponseDto = unsupported()
        override suspend fun sentReceipts(deviceId: String): SentReceiptsResponseDto = unsupported()
        override suspend fun receipt(id: String, body: ReceiptRequestDto): ReceiptResponseDto = unsupported()
        override suspend fun presignUpload(body: PresignUploadRequestDto): PresignUploadResponseDto = unsupported()
        override suspend fun represignUpload(blobId: String, body: RepresignUploadRequestDto): RepresignUploadResponseDto = unsupported()
        override suspend fun presignDownload(body: PresignDownloadRequestDto): PresignDownloadResponseDto = unsupported()
        override suspend fun grantP2pAttachments(body: P2pAttachmentGrantRequestDto): P2pAttachmentGrantResponseDto = unsupported()
        override suspend fun commitP2pAttachments(body: P2pAttachmentCommitRequestDto): P2pAttachmentCommitResponseDto = unsupported()
        override suspend fun completeUpload(blobId: String, body: CompleteUploadRequestDto): CompleteUploadResponseDto = unsupported()
        override suspend fun createGroup(body: CreateGroupRequestDto): GroupDetailResponseDto = unsupported()
        override suspend fun groups(bubbleId: String?): GroupsResponseDto = unsupported()
        override suspend fun group(groupId: String): GroupDetailResponseDto = unsupported()
        override suspend fun addGroupMember(groupId: String, body: AddGroupMemberRequestDto): GroupMemberDto = unsupported()
        override suspend fun removeGroupMember(groupId: String, userId: String): StatusResponseDto = unsupported()
        override suspend fun sendGroupMessage(groupId: String, body: SendGroupMessageRequestDto): GroupMessageResponseDto = unsupported()
        override suspend fun pendingGroupMessages(groupId: String): PendingGroupMessagesResponseDto = unsupported()
        override suspend fun groupReceipt(groupId: String, messageId: String, body: GroupReceiptRequestDto): StatusResponseDto = unsupported()
        override suspend fun createChannel(body: CreateChannelRequestDto): ChannelDto = unsupported()
        override suspend fun channels(bubbleId: String?): ChannelsResponseDto = unsupported()
        override suspend fun channel(channelId: String): ChannelDto = unsupported()
        override suspend fun channelSubscribers(channelId: String): ChannelSubscribersResponseDto = unsupported()
        override suspend fun subscribeChannel(channelId: String): StatusResponseDto = unsupported()
        override suspend fun unsubscribeChannel(channelId: String): StatusResponseDto = unsupported()
        override suspend fun createChannelPost(channelId: String, body: CreateChannelPostRequestDto): ChannelPostResponseDto = unsupported()
        override suspend fun pendingChannelPosts(channelId: String): PendingChannelPostsResponseDto = unsupported()
        override suspend fun createCall(body: CreateCallRequestDto): CallResponseDto = unsupported()
        override suspend fun acceptCall(callId: String): StatusResponseDto = unsupported()
        override suspend fun rejectCall(callId: String): StatusResponseDto = unsupported()
        override suspend fun hangupCall(callId: String): StatusResponseDto = unsupported()
        override suspend fun callOffer(callId: String, body: SdpRequestDto): StatusResponseDto = unsupported()
        override suspend fun callAnswer(callId: String, body: SdpRequestDto): StatusResponseDto = unsupported()
        override suspend fun addIceCandidates(callId: String, body: IceCandidatesRequestDto): StatusResponseDto = unsupported()
        override suspend fun iceCandidates(callId: String): IceCandidatesResponseDto = unsupported()
        override suspend fun callSignaling(callId: String): CallSignalingEventsResponseDto = unsupported()
        override suspend fun turnCredentials(): TurnCredentialsResponseDto = unsupported()
        override suspend fun androidRelease(channel: String): AndroidReleaseResponseDto = unsupported()
        override suspend fun myPlan(): PlanDto = unsupported()
        override suspend fun myUsage(): UsageDto = unsupported()
        override suspend fun supportConfig(): SupportConfigDto = unsupported()
        override suspend fun officialAnnouncements(): OfficialAnnouncementsDto = unsupported()
        override suspend fun readOfficialAnnouncement(id: String): StatusResponseDto = unsupported()
        override suspend fun dismissOfficialAnnouncement(id: String): StatusResponseDto = unsupported()
    }
}

private fun unsupported(): Nothing = error("not used")
