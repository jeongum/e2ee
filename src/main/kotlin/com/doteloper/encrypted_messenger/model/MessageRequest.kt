package com.doteloper.encrypted_messenger.model

data class MessageRequest(
    val senderId: String,
    val receiverId: String,
    val message: String
)