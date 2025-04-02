package com.doteloper.encrypted_messenger.service

import org.springframework.stereotype.Service
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

@Service
class EncryptionService {
    /**
     *  AES: 대칭키 블록 암호화 알고리즘
     *  iv: 동일한 암호화 결과가 나오지 않도록 붙여주는 랜덤 값 (키랑 무관)
     */

    //  AES 대칭키 생성: 256 비트 길이 (메세지 본문 암호화 하는데 사용)
    fun generateAESKey(): SecretKey {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256)
        return keyGen.generateKey()
    }

    // 평문 메세지 암호화: 대칭키(secretKey) 사용
    fun encryptAESWithIVPrefixed(plainText: String, secretKey: SecretKey): String {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")     // 암호 처리기 생성
        val ivBytes = ByteArray(16)     // 16 바이트 짜리 배열 생성
        SecureRandom().nextBytes(ivBytes)   // ivBytes 배열에 무작위 값 채움
        val ivSpec = IvParameterSpec(ivBytes)

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)     // 암호 처리기 초기화
        val encryptedBytes = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

        val combined = ivBytes + encryptedBytes     // 메세지 앞에 16 바이트를 붙여서, 메세지 생성
        return Base64.getEncoder().encodeToString(combined)
    }

    // 메제지 복호화: 대칭키(SecretKey) 사용
    fun decryptAESWithIVPrefixed(encryptedCombined: String, secretKey: SecretKey): String {
        val combinedBytes = Base64.getDecoder().decode(encryptedCombined)
        val iv = combinedBytes.copyOfRange(0, 16)   // 암호화에 사용한 대칭키 추출
        val encrypted = combinedBytes.copyOfRange(16, combinedBytes.size)   // 암호화된 실제 메세지 추출

        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")     // 암호 처리기 생성
        val ivSpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec) // 암호 처리기 초기화 - Decrypt 모드
        val decryptedBytes = cipher.doFinal(encrypted)

        return String(decryptedBytes, Charsets.UTF_8)
    }

    // 대칭키 암호화: 수신자의 공개키로 암호화 하여 전달할 수 있도록 함
    fun encryptAESKeyWithRSA(secretKey: SecretKey, publicKey: PublicKey): String {
        val cipher = Cipher.getInstance("RSA")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedKey = cipher.doFinal(secretKey.encoded)
        return Base64.getEncoder().encodeToString(encryptedKey)
    }

    // 대칭키 복호화: 비공개키로 복호화
    fun decryptAESKeyWithRSA(encryptedAesKey: String, privateKey: PrivateKey): SecretKey {
        val cipher = Cipher.getInstance("RSA")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        val decodedKey = cipher.doFinal(Base64.getDecoder().decode(encryptedAesKey))
        return SecretKeySpec(decodedKey, "AES")
    }
}