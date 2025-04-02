package com.doteloper.encrypted_messenger.controller.dto

data class MessageRequest(val senderId: String, val receiverId: String, val message: String)