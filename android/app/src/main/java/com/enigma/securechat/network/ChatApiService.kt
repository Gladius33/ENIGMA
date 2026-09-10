package com.enigma.securechat.network

import com.enigma.securechat.network.dto.AuthRequestDto
import com.enigma.securechat.network.dto.AuthResponseDto
import com.enigma.securechat.network.dto.AddContactRequestDto
import com.enigma.securechat.network.dto.AddGroupMemberRequestDto
import com.enigma.securechat.network.dto.CallResponseDto
import com.enigma.securechat.network.dto.CallSignalingEventsResponseDto
import com.enigma.securechat.network.dto.ChannelDto
import com.enigma.securechat.network.dto.ChannelPostResponseDto
import com.enigma.securechat.network.dto.ChannelSubscribersResponseDto
import com.enigma.securechat.network.dto.ChannelsResponseDto
import com.enigma.securechat.network.dto.ClaimPreKeyResponseDto
import com.enigma.securechat.network.dto.CompleteUploadRequestDto
import com.enigma.securechat.network.dto.CompleteUploadResponseDto
import com.enigma.securechat.network.dto.ContactsResponseDto
import com.enigma.securechat.network.dto.CreateCallRequestDto
import com.enigma.securechat.network.dto.CreateChannelPostRequestDto
import com.enigma.securechat.network.dto.CreateChannelRequestDto
import com.enigma.securechat.network.dto.CreateGroupRequestDto
import com.enigma.securechat.network.dto.DeviceRegisterRequestDto
import com.enigma.securechat.network.dto.DeviceRegisterResponseDto
import com.enigma.securechat.network.dto.DevicesResponseDto
import com.enigma.securechat.network.dto.FcmTokenRequestDto
import com.enigma.securechat.network.dto.GroupDetailResponseDto
import com.enigma.securechat.network.dto.GroupMessageResponseDto
import com.enigma.securechat.network.dto.GroupMemberDto
import com.enigma.securechat.network.dto.GroupsResponseDto
import com.enigma.securechat.network.dto.GroupReceiptRequestDto
import com.enigma.securechat.network.dto.HealthResponseDto
import com.enigma.securechat.network.dto.IceCandidatesRequestDto
import com.enigma.securechat.network.dto.IceCandidatesResponseDto
import com.enigma.securechat.network.dto.CreateIdentityRequestDto
import com.enigma.securechat.network.dto.DeleteIdentityResponseDto
import com.enigma.securechat.network.dto.IdentityCheckResponseDto
import com.enigma.securechat.network.dto.IdentityResponseDto
import com.enigma.securechat.network.dto.KeyBundleResponseDto
import com.enigma.securechat.network.dto.KeyStatusResponseDto
import com.enigma.securechat.network.dto.PendingMessagesResponseDto
import com.enigma.securechat.network.dto.PendingChannelPostsResponseDto
import com.enigma.securechat.network.dto.PendingGroupMessagesResponseDto
import com.enigma.securechat.network.dto.P2pAttachmentCommitRequestDto
import com.enigma.securechat.network.dto.P2pAttachmentCommitResponseDto
import com.enigma.securechat.network.dto.P2pAttachmentGrantRequestDto
import com.enigma.securechat.network.dto.P2pAttachmentGrantResponseDto
import com.enigma.securechat.network.dto.PresignDownloadRequestDto
import com.enigma.securechat.network.dto.PresignDownloadResponseDto
import com.enigma.securechat.network.dto.PresignUploadRequestDto
import com.enigma.securechat.network.dto.PresignUploadResponseDto
import com.enigma.securechat.network.dto.RepresignUploadRequestDto
import com.enigma.securechat.network.dto.RepresignUploadResponseDto
import com.enigma.securechat.network.dto.RecoverCompleteRequestDto
import com.enigma.securechat.network.dto.RecoverStartRequestDto
import com.enigma.securechat.network.dto.RecoverStartResponseDto
import com.enigma.securechat.network.dto.ReceiptRequestDto
import com.enigma.securechat.network.dto.ReceiptResponseDto
import com.enigma.securechat.network.dto.ResolveUserResponseDto
import com.enigma.securechat.network.dto.SendGroupMessageRequestDto
import com.enigma.securechat.network.dto.SendMessageRequestDto
import com.enigma.securechat.network.dto.SendMessageResponseDto
import com.enigma.securechat.network.dto.SentReceiptsResponseDto
import com.enigma.securechat.network.dto.SdpRequestDto
import com.enigma.securechat.network.dto.StatusResponseDto
import com.enigma.securechat.network.dto.TurnCredentialsResponseDto
import com.enigma.securechat.network.dto.UploadKeysRequestDto
import com.enigma.securechat.network.dto.UploadKeysResponseDto
import com.enigma.securechat.network.dto.VersionResponseDto
import com.enigma.securechat.network.dto.ContactDto
import com.enigma.securechat.network.dto.AndroidReleaseResponseDto
import com.enigma.securechat.network.dto.AddBubbleRelayRequestDto
import com.enigma.securechat.network.dto.PlanDto
import com.enigma.securechat.network.dto.UsageDto
import com.enigma.securechat.network.dto.SupportConfigDto
import com.enigma.securechat.network.dto.OfficialAnnouncementsDto
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query
import com.enigma.securechat.network.dto.BubbleDto
import com.enigma.securechat.network.dto.BubbleMembersResponseDto
import com.enigma.securechat.network.dto.BubbleRelayDto
import com.enigma.securechat.network.dto.BubbleRelaysResponseDto
import com.enigma.securechat.network.dto.BubblesResponseDto
import com.enigma.securechat.network.dto.CreateBubbleRequestDto
import com.enigma.securechat.network.dto.CreateCustomRelayRequestDto
import com.enigma.securechat.network.dto.RelayDto
import com.enigma.securechat.network.dto.RelaysResponseDto

interface ChatApiService {
    @GET("health")
    suspend fun health(): HealthResponseDto

    @GET("version")
    suspend fun version(): VersionResponseDto

    @POST("v1/auth/register")
    suspend fun register(@Body body: AuthRequestDto): AuthResponseDto

    @POST("v1/auth/login")
    suspend fun login(@Body body: AuthRequestDto): AuthResponseDto

    @POST("v1/devices/register")
    suspend fun registerDevice(@Body body: DeviceRegisterRequestDto): DeviceRegisterResponseDto

    @POST("v1/devices/fcm-token")
    suspend fun updateFcmToken(@Body body: FcmTokenRequestDto): StatusResponseDto

    @GET("v1/devices")
    suspend fun devices(): DevicesResponseDto

    @DELETE("v1/devices/{device_id}")
    suspend fun deleteDevice(@Path("device_id") deviceId: String): StatusResponseDto

    @POST("v1/keys/upload")
    suspend fun uploadKeys(@Body body: UploadKeysRequestDto): UploadKeysResponseDto

    @GET("v1/keys/{user_id}")
    suspend fun getKeys(@Path("user_id") userId: String): KeyBundleResponseDto

    @GET("v1/keys/{user_id}/devices")
    suspend fun discoverKeys(@Path("user_id") userId: String): KeyBundleResponseDto

    @POST("v1/keys/{user_id}/devices/{device_id}/claim-prekey")
    suspend fun claimPreKey(
        @Path("user_id") userId: String,
        @Path("device_id") deviceId: String,
    ): ClaimPreKeyResponseDto

    @GET("v1/keys/status")
    suspend fun keyStatus(): KeyStatusResponseDto

    @GET("v1/users/resolve/{public_id}")
    suspend fun resolveUser(@Path("public_id") publicId: String): ResolveUserResponseDto

    @GET("v1/identities/check")
    suspend fun checkIdentity(@Query("handle") handle: String): IdentityCheckResponseDto

    @POST("v1/identities")
    suspend fun createIdentity(@Body body: CreateIdentityRequestDto): IdentityResponseDto

    @POST("v1/identities/recover/start")
    suspend fun recoverStart(@Body body: RecoverStartRequestDto): RecoverStartResponseDto

    @POST("v1/identities/recover/complete")
    suspend fun recoverComplete(@Body body: RecoverCompleteRequestDto): IdentityResponseDto

    @DELETE("v1/identities/me")
    suspend fun deleteIdentity(): DeleteIdentityResponseDto

    @POST("v1/contacts")
    suspend fun addContact(@Body body: AddContactRequestDto): ContactDto

    @GET("v1/contacts")
    suspend fun contacts(): ContactsResponseDto

    @DELETE("v1/contacts/{contact_user_id}")
    suspend fun deleteContact(@Path("contact_user_id") contactUserId: String): StatusResponseDto

    @GET("v1/bubbles")
    suspend fun bubbles(): BubblesResponseDto

    @POST("v1/bubbles")
    suspend fun createBubble(@Body body: CreateBubbleRequestDto): BubbleDto

    @GET("v1/bubbles/{bubble_id}")
    suspend fun bubble(@Path("bubble_id") bubbleId: String): BubbleDto

    @GET("v1/bubbles/{bubble_id}/members")
    suspend fun bubbleMembers(@Path("bubble_id") bubbleId: String): BubbleMembersResponseDto

    @GET("v1/bubbles/{bubble_id}/relays")
    suspend fun bubbleRelays(@Path("bubble_id") bubbleId: String): BubbleRelaysResponseDto

    @POST("v1/bubbles/{bubble_id}/relays")
    suspend fun addBubbleRelay(
        @Path("bubble_id") bubbleId: String,
        @Body body: AddBubbleRelayRequestDto,
    ): BubbleRelayDto

    @GET("v1/relays")
    suspend fun relays(): RelaysResponseDto

    @POST("v1/relays/custom")
    suspend fun createCustomRelay(@Body body: CreateCustomRelayRequestDto): RelayDto

    @GET("v1/relays/official-descriptor")
    suspend fun officialRelayDescriptor(): RelayDto

    @POST("v1/messages")
    suspend fun sendMessage(@Body body: SendMessageRequestDto): SendMessageResponseDto

    @GET("v1/messages/pending")
    suspend fun pendingMessages(@Query("device_id") deviceId: String): PendingMessagesResponseDto

    @GET("v1/messages/receipts")
    suspend fun sentReceipts(@Query("device_id") deviceId: String): SentReceiptsResponseDto

    @POST("v1/messages/{id}/receipt")
    suspend fun receipt(
        @Path("id") id: String,
        @Body body: ReceiptRequestDto,
    ): ReceiptResponseDto

    @POST("v1/attachments/presign-upload")
    suspend fun presignUpload(@Body body: PresignUploadRequestDto): PresignUploadResponseDto

    @POST("v1/attachments/{blob_id}/presign-upload")
    suspend fun represignUpload(
        @Path("blob_id") blobId: String,
        @Body body: RepresignUploadRequestDto,
    ): RepresignUploadResponseDto

    @POST("v1/attachments/presign-download")
    suspend fun presignDownload(@Body body: PresignDownloadRequestDto): PresignDownloadResponseDto

    @POST("v1/attachments/p2p-grant")
    suspend fun grantP2pAttachments(
        @Body body: P2pAttachmentGrantRequestDto,
    ): P2pAttachmentGrantResponseDto

    @POST("v1/attachments/p2p-commit")
    suspend fun commitP2pAttachments(
        @Body body: P2pAttachmentCommitRequestDto,
    ): P2pAttachmentCommitResponseDto

    @POST("v1/attachments/{blob_id}/complete")
    suspend fun completeUpload(
        @Path("blob_id") blobId: String,
        @Body body: CompleteUploadRequestDto,
    ): CompleteUploadResponseDto

    @POST("v1/groups")
    suspend fun createGroup(@Body body: CreateGroupRequestDto): GroupDetailResponseDto

    @GET("v1/groups")
    suspend fun groups(@Query("bubble_id") bubbleId: String? = null): GroupsResponseDto

    @GET("v1/groups/{group_id}")
    suspend fun group(@Path("group_id") groupId: String): GroupDetailResponseDto

    @POST("v1/groups/{group_id}/members")
    suspend fun addGroupMember(
        @Path("group_id") groupId: String,
        @Body body: AddGroupMemberRequestDto,
    ): GroupMemberDto

    @DELETE("v1/groups/{group_id}/members/{user_id}")
    suspend fun removeGroupMember(
        @Path("group_id") groupId: String,
        @Path("user_id") userId: String,
    ): StatusResponseDto

    @POST("v1/groups/{group_id}/messages")
    suspend fun sendGroupMessage(
        @Path("group_id") groupId: String,
        @Body body: SendGroupMessageRequestDto,
    ): GroupMessageResponseDto

    @GET("v1/groups/{group_id}/messages/pending")
    suspend fun pendingGroupMessages(@Path("group_id") groupId: String): PendingGroupMessagesResponseDto

    @POST("v1/groups/{group_id}/messages/{message_id}/receipt")
    suspend fun groupReceipt(
        @Path("group_id") groupId: String,
        @Path("message_id") messageId: String,
        @Body body: GroupReceiptRequestDto,
    ): StatusResponseDto

    @POST("v1/channels")
    suspend fun createChannel(@Body body: CreateChannelRequestDto): ChannelDto

    @GET("v1/channels")
    suspend fun channels(@Query("bubble_id") bubbleId: String? = null): ChannelsResponseDto

    @GET("v1/channels/{channel_id}")
    suspend fun channel(@Path("channel_id") channelId: String): ChannelDto

    @GET("v1/channels/{channel_id}/subscribers")
    suspend fun channelSubscribers(@Path("channel_id") channelId: String): ChannelSubscribersResponseDto

    @POST("v1/channels/{channel_id}/subscribe")
    suspend fun subscribeChannel(@Path("channel_id") channelId: String): StatusResponseDto

    @DELETE("v1/channels/{channel_id}/subscribe")
    suspend fun unsubscribeChannel(@Path("channel_id") channelId: String): StatusResponseDto

    @POST("v1/channels/{channel_id}/posts")
    suspend fun createChannelPost(
        @Path("channel_id") channelId: String,
        @Body body: CreateChannelPostRequestDto,
    ): ChannelPostResponseDto

    @GET("v1/channels/{channel_id}/posts/pending")
    suspend fun pendingChannelPosts(@Path("channel_id") channelId: String): PendingChannelPostsResponseDto

    @POST("v1/calls")
    suspend fun createCall(@Body body: CreateCallRequestDto): CallResponseDto

    @POST("v1/calls/{call_id}/accept")
    suspend fun acceptCall(@Path("call_id") callId: String): StatusResponseDto

    @POST("v1/calls/{call_id}/reject")
    suspend fun rejectCall(@Path("call_id") callId: String): StatusResponseDto

    @POST("v1/calls/{call_id}/hangup")
    suspend fun hangupCall(@Path("call_id") callId: String): StatusResponseDto

    @POST("v1/calls/{call_id}/offer")
    suspend fun callOffer(@Path("call_id") callId: String, @Body body: SdpRequestDto): StatusResponseDto

    @POST("v1/calls/{call_id}/answer")
    suspend fun callAnswer(@Path("call_id") callId: String, @Body body: SdpRequestDto): StatusResponseDto

    @POST("v1/calls/{call_id}/ice-candidates")
    suspend fun addIceCandidates(
        @Path("call_id") callId: String,
        @Body body: IceCandidatesRequestDto,
    ): StatusResponseDto

    @GET("v1/calls/{call_id}/ice-candidates")
    suspend fun iceCandidates(@Path("call_id") callId: String): IceCandidatesResponseDto

    @GET("v1/calls/{call_id}/signaling")
    suspend fun callSignaling(@Path("call_id") callId: String): CallSignalingEventsResponseDto

    @POST("v1/turn/credentials")
    suspend fun turnCredentials(): TurnCredentialsResponseDto

    @GET("v1/releases/android")
    suspend fun androidRelease(@Query("channel") channel: String = "stable"): AndroidReleaseResponseDto
    @GET("v1/me/plan") suspend fun myPlan(): PlanDto
    @GET("v1/me/usage") suspend fun myUsage(): UsageDto
    @GET("v1/support/config") suspend fun supportConfig(): SupportConfigDto
    @GET("v1/official/announcements/pending") suspend fun officialAnnouncements(): OfficialAnnouncementsDto
    @POST("v1/official/announcements/{id}/read") suspend fun readOfficialAnnouncement(@Path("id") id:String): StatusResponseDto
    @POST("v1/official/announcements/{id}/dismiss") suspend fun dismissOfficialAnnouncement(@Path("id") id:String): StatusResponseDto
}
