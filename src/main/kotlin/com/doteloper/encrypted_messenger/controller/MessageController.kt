package com.doteloper.encrypted_messenger.controller

import com.doteloper.encrypted_messenger.controller.dto.EncryptedPayload
import com.doteloper.encrypted_messenger.controller.dto.MessageRequest
import com.doteloper.encrypted_messenger.controller.dto.MessageResponse
import com.doteloper.encrypted_messenger.controller.dto.PublicKeyRegisterRequest
import com.doteloper.encrypted_messenger.service.EncryptionService
import org.springframework.web.bind.annotation.*
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey

@RestController
@RequestMapping("/api")
class MessageController(
    private val encryptionService: EncryptionService,
) {
    private val publicKeyMap: MutableMap<String, PublicKey> = mutableMapOf()
    private val privateKeyMap: MutableMap<String, PrivateKey> = mutableMapOf()
    private val messageBox: MutableMap<String, MutableList<EncryptedPayload>> = mutableMapOf()

    /**
     * 일반 클라-서버 관계라면 서버는 단순히 클라에서 전송한 publicKey만 들고 있으며, keyPair생성, 메세지 암/복호화의 롤은 모두 클라가 갖는다.
     * 또한, 비대칭키 암/복호화는 많은 computing 자원이 필요하기 때문에, 비대칭키로 암호화된 대칭키를 매번 변경하지 않는다.
     * 즉, 클라에서 비대칭키로 복호화한 메세징 대칭키를 Caching 해놓고, 빠르게 메세지를 복호화 할 수 있도록 한다.
     */

    @PostMapping("/register")
    fun registerUser(@RequestBody request: PublicKeyRegisterRequest): String {
        // userId에 대한 KeyPair 생성
        val keyPairGen = KeyPairGenerator.getInstance("RSA")
        keyPairGen.initialize(2048)
        val keyPair = keyPairGen.generateKeyPair()

        publicKeyMap[request.userId] = keyPair.public
        privateKeyMap[request.userId] = keyPair.private

        return "User ${request.userId} registered with key pair"
    }

    @PostMapping("/send")
    fun sendMessage(@RequestBody request: MessageRequest): String {
        val receiverPublicKey = publicKeyMap[request.receiverId] ?: error("Receiver not found")
        val aesKey = encryptionService.generateAESKey()

        // 메세지 암호화(대칭키)
        val encryptedMessage = encryptionService.encryptAESWithIVPrefixed(request.message, aesKey)

        // 대칭키 암호화(비대칭키)
        val encryptedAesKey = encryptionService.encryptAESKeyWithRSA(aesKey, receiverPublicKey)

        val payload = EncryptedPayload(request.senderId, encryptedMessage, encryptedAesKey)
        messageBox.computeIfAbsent(request.receiverId) { mutableListOf() }.add(payload)

        return "Message sent securely to ${request.receiverId}"
    }

    @GetMapping("/messages/{userId}")
    fun receiveMessages(@PathVariable userId: String): List<MessageResponse> {
        val privateKey = privateKeyMap[userId] ?: error("Private key not found for $userId")
        val messages = messageBox[userId] ?: return emptyList()

        return messages.map { payload ->
            // 대칭키 복호화(비대칭키)
            val aesKey = encryptionService.decryptAESKeyWithRSA(payload.encryptedAesKey, privateKey)

            // 메세지 복호화(대칭키)
            val plainText = encryptionService.decryptAESWithIVPrefixed(payload.encryptedMessage, aesKey)
            MessageResponse("${payload.senderId}: $plainText")
        }
    }
}




