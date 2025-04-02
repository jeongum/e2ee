package com.doteloper.encrypted_messenger.controller.dto

data class EncryptedPayload(
    val senderId: String,
    val encryptedMessage: String,
    val encryptedAesKey: String
)
