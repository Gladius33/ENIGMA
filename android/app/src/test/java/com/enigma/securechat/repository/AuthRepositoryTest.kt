package com.enigma.securechat.repository

import com.enigma.securechat.data.repository.AuthRepository
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.domain.model.UserSession
import com.enigma.securechat.network.ChatApiService
import com.enigma.securechat.network.dto.*
import com.enigma.securechat.storage.SessionPersistence
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AuthRepositoryTest {
    @Test
    fun registerPersistsSession() = runTest {
        val store = FakeSessionStore()
        val repository = AuthRepository(FakeApi(), store)

        val result = repository.register("alice", "correct horse battery staple")

        assertTrue(result is AppResult.Ok)
        assertEquals("user-1", store.saved?.userId)
        assertEquals("alice", store.saved?.publicId)
    }

    private class FakeSessionStore : SessionPersistence {
        var saved: UserSession? = null
        override suspend fun saveSession(value: UserSession) {
            saved = value
        }

        override suspend fun clearSession() {
            saved = null
        }
    }

    private class FakeApi : ChatApiService {
        override suspend fun health(): HealthResponseDto = unsupported()
        override suspend fun version(): VersionResponseDto = unsupported()

        override suspend fun register(body: AuthRequestDto): AuthResponseDto =
            AuthResponseDto("session", "Bearer", 3600, UserDto("user-1", body.publicId))

        override suspend fun login(body: AuthRequestDto): AuthResponseDto =
            AuthResponseDto("session", "Bearer", 3600, UserDto("user-1", body.publicId))

        override suspend fun registerDevice(body: DeviceRegisterRequestDto): DeviceRegisterResponseDto = unsupported()
        override suspend fun authorizeLinkedDesktop(body: AuthorizeLinkedDesktopRequestDto): LinkedDesktopResponseDto = unsupported()
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
        override suspend fun deleteIdentity(): DeleteIdentityResponseDto = unsupported()
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

        private fun unsupported(): Nothing = error("not used")
    }
}
