package com.doteloper.encrypted_messenger.model

data class EncryptedMessage(
    val encryptedMessage: String,     // AES로 암호화된 메시지
    val encryptedAesKey: String,      // RSA로 암호화된 AES 키
    val iv: String                    // AES IV (초기화 벡터)
)