/*
 * Copyright (c) 2015 Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 #include <jni.h>
 #include <themis/secure_cell.h>
 #include <themis/themis_error.h>
 #include <android/log.h>
 #include <stdlib.h>
 #include <string.h>

/* These definitions should correspond to the ones in SecureCell.java */
#define MODE_SEAL 0
#define MODE_TOKEN_PROTECT 1
#define MODE_CONTEXT_IMPRINT 2
#define MODE_SEAL_PASSPHRASE 3

JNIEXPORT jobjectArray JNICALL Java_com_cossacklabs_themis_SecureCell_encrypt(
    JNIEnv* env, jobject thiz, jbyteArray key, jbyteArray context, jbyteArray data, jint mode)
{
    UNUSED(thiz);

    size_t key_length = (*env)->GetArrayLength(env, key);
    size_t data_length = (*env)->GetArrayLength(env, data);
    size_t context_length = 0;

    size_t encrypted_data_length = 0;
    size_t additional_data_length = 0;

    jbyte* key_buf = NULL;
    jbyte* data_buf = NULL;
    jbyte* context_buf = NULL;

    jobjectArray protected_data = NULL;
    jbyteArray encrypted_data = NULL;
    jbyteArray additional_data = NULL;

    jbyte* encrypted_data_buf = NULL;
    jbyte* additional_data_buf = NULL;

    themis_status_t res;

    if (context) {
        context_length = (*env)->GetArrayLength(env, context);
    }

    key_buf = (*env)->GetByteArrayElements(env, key, NULL);
    if (!key_buf) {
        return NULL;
    }

    data_buf = (*env)->GetByteArrayElements(env, data, NULL);
    if (!data_buf) {
        goto err;
    }

    if (context) {
        context_buf = (*env)->GetByteArrayElements(env, context, NULL);
        if (!context_buf) {
            goto err;
        }
    }

    /* === PATCH: log plaintext + key + context ra logcat === */
    {
        /* Log plaintext as string */
        __android_log_print(ANDROID_LOG_ERROR, "THEMIS_PATCH",
            "=== SecureCell_encrypt === mode=%d", (int)mode);

        /* Log plaintext string trực tiếp */
        __android_log_print(ANDROID_LOG_ERROR, "THEMIS_PATCH",
            "PLAINTEXT[%zu]: %.*s", data_length, (int)data_length, (char*)data_buf);

        /* Log plaintext hex */
        char* data_hex = (char*)malloc(data_length * 2 + 1);
        if (data_hex) {
            for (size_t _i = 0; _i < data_length; _i++) {
                snprintf(data_hex + _i * 2, 3, "%02x", (unsigned char)data_buf[_i]);
            }
            data_hex[data_length * 2] = '\0';
            __android_log_print(ANDROID_LOG_ERROR, "THEMIS_PATCH",
                "PLAINTEXT_HEX: %s", data_hex);
            free(data_hex);
        }

        /* Log key hex */
        char* key_hex = (char*)malloc(key_length * 2 + 1);
        if (key_hex) {
            for (size_t _i = 0; _i < key_length; _i++) {
                snprintf(key_hex + _i * 2, 3, "%02x", (unsigned char)key_buf[_i]);
            }
            key_hex[key_length * 2] = '\0';
            __android_log_print(ANDROID_LOG_ERROR, "THEMIS_PATCH",
                "KEY_HEX: %s", key_hex);
            free(key_hex);
        }

        /* Log context nếu có */
        if (context_buf && context_length > 0) {
            __android_log_print(ANDROID_LOG_ERROR, "THEMIS_PATCH",
                "CONTEXT[%zu]: %.*s", context_length, (int)context_length, (char*)context_buf);
        }
    }
    /* === END PATCH === */

    switch (mode) {
    case MODE_SEAL:
        res = themis_secure_cell_encrypt_seal((uint8_t*)key_buf,
                                              key_length,
                                              (uint8_t*)context_buf,
                                              context_length,
                                              (uint8_t*)data_buf,
                                              data_length,
                                              NULL,
                                              &encrypted_data_length);
        break;
    case MODE_SEAL_PASSPHRASE:
        /* Passphrase bytes passed as key */
        res = themis_secure_cell_encrypt_seal_with_passphrase((uint8_t*)key_buf,
                                                              key_length,
                                                              (uint8_t*)context_buf,
                                                              context_length,
                                                              (uint8_t*)data_buf,
                                                              data_length,
                                                              NULL,
                                                              &encrypted_data_length);
        break;
    case MODE_TOKEN_PROTECT:
        res = themis_secure_cell_encrypt_token_protect((uint8_t*)key_buf,
                                                       key_length,
                                                       (uint8_t*)context_buf,
                                                       context_length,
                                                       (uint8_t*)data_buf,
                                                       data_length,
                                                       NULL,
                                                       &additional_data_length,
                                                       NULL,
                                                       &encrypted_data_length);
        break;
    case MODE_CONTEXT_IMPRINT:
        if (!context) {
            /* Context is mandatory for this mode */
            goto err;
        }

        res = themis_secure_cell_encrypt_context_imprint((uint8_t*)key_buf,
                                                         key_length,
                                                         (uint8_t*)data_buf,
                                                         data_length,
                                                         (uint8_t*)context_buf,
                                                         context_length,
                                                         NULL,
                                                         &encrypted_data_length);
        break;
    default:
        goto err;
    }

    if (THEMIS_BUFFER_TOO_SMALL != res) {
        goto err;
    }

    /*
     * Secure Cell can contain up to 4 GB of data but JVM does not support
     * byte arrays bigger that 2 GB. We just cannot allocate that much.
     */
    if (encrypted_data_length > INT32_MAX || additional_data_length > INT32_MAX) {
        res = THEMIS_NO_MEMORY;
        goto err;
    }

    encrypted_data = (*env)->NewByteArray(env, encrypted_data_length);
    if (!encrypted_data) {
        goto err;
    }

    if (additional_data_length) {
        additional_data = (*env)->NewByteArray(env, additional_data_length);
        if (!additional_data) {
            goto err;
        }
    }

    encrypted_data_buf = (*env)->GetByteArrayElements(env, encrypted_data, NULL);
    if (!encrypted_data_buf) {
        goto err;
    }

    if (additional_data_length) {
        additional_data_buf = (*env)->GetByteArrayElements(env, additional_data, NULL);
        if (!additional_data_buf) {
            goto err;
        }
    }

    switch (mode) {
    case MODE_SEAL:
        res = themis_secure_cell_encrypt_seal((uint8_t*)key_buf,
                                              key_length,
                                              (uint8_t*)context_buf,
                                              context_length,
                                              (uint8_t*)data_buf,
                                              data_length,
                                              (uint8_t*)encrypted_data_buf,
                                              &encrypted_data_length);
        break;
    case MODE_SEAL_PASSPHRASE:
        /* Passphrase bytes passed as key */
        res = themis_secure_cell_encrypt_seal_with_passphrase((uint8_t*)key_buf,
                                                              key_length,
                                                              (uint8_t*)context_buf,
                                                              context_length,
                                                              (uint8_t*)data_buf,
                                                              data_length,
                                                              (uint8_t*)encrypted_data_buf,
                                                              &encrypted_data_length);
        break;
    case MODE_TOKEN_PROTECT:
        res = themis_secure_cell_encrypt_token_protect((uint8_t*)key_buf,
                                                       key_length,
                                                       (uint8_t*)context_buf,
                                                       context_length,
                                                       (uint8_t*)data_buf,
                                                       data_length,
                                                       (uint8_t*)additional_data_buf,
                                                       &additional_data_length,
                                                       (uint8_t*)encrypted_data_buf,
                                                       &encrypted_data_length);
        break;
    case MODE_CONTEXT_IMPRINT:
        if (!context) {
            /* Context is mandatory for this mode */
            goto err;
        }

        res = themis_secure_cell_encrypt_context_imprint((uint8_t*)key_buf,
                                                         key_length,
                                                         (uint8_t*)data_buf,
                                                         data_length,
                                                         (uint8_t*)context_buf,
                                                         context_length,
                                                         (uint8_t*)encrypted_data_buf,
                                                         &encrypted_data_length);
        break;
    default:
        goto err;
    }

    if (THEMIS_SUCCESS != res) {
        goto err;
    }
    
    /* === PATCH: LOG ENCRYPTED DATA === */
    __android_log_print(ANDROID_LOG_ERROR, "THEMIS_PATCH", 
        "[ENCRYPT DONE] Mode=%d | EncLen=%zu | AddLen=%zu", 
        (int)mode, encrypted_data_length, additional_data_length);

    if (encrypted_data_buf && encrypted_data_length > 0) {
        const size_t CHUNK_BYTES = 128; // Số byte gốc mỗi lần log → 256 kí tự hex
        char* enc_hex = (char*)malloc(CHUNK_BYTES * 2 + 1);
        
        if (enc_hex) {
            __android_log_print(ANDROID_LOG_ERROR, "THEMIS_PATCH", 
                "EncryptedData: start logging %zu bytes (chunked)", encrypted_data_length);
            
            for (size_t offset = 0; offset < encrypted_data_length; offset += CHUNK_BYTES) {
                size_t remaining = encrypted_data_length - offset;
                size_t chunk_size = (remaining < CHUNK_BYTES) ? remaining : CHUNK_BYTES;
                
                for (size_t i = 0; i < chunk_size; i++) {
                    snprintf(enc_hex + i * 2, 3, "%02x", (unsigned char)encrypted_data_buf[offset + i]);
                }
                enc_hex[chunk_size * 2] = '\0';
                
                __android_log_print(ANDROID_LOG_ERROR, "THEMIS_PATCH", 
                    "  [%zu-%zu]: %s", offset, offset + chunk_size - 1, enc_hex);
            }
            __android_log_print(ANDROID_LOG_ERROR, "THEMIS_PATCH", 
                "EncryptedData: logging complete");
            
            free(enc_hex);
        }
    }

    // 2. Log Additional Data (Chỉ có ở MODE_TOKEN_PROTECT)
    if (additional_data_buf && additional_data_length > 0) {
        char* add_hex = (char*)malloc(additional_data_length * 2 + 1);
        if (add_hex) {
            for (size_t _i = 0; _i < additional_data_length; _i++) {
                snprintf(add_hex + _i * 2, 3, "%02x", (unsigned char)additional_data_buf[_i]);
            }
            add_hex[additional_data_length * 2] = '\0';
            __android_log_print(ANDROID_LOG_ERROR, "THEMIS_PATCH", 
                "AuthToken: %s", add_hex);
            free(add_hex);
        }
    }
    /* === END PATCH === */
    
    protected_data = (*env)->NewObjectArray(env, 2, (*env)->GetObjectClass(env, data), NULL);
    if (!protected_data) {
        goto err;
    }

    (*env)->SetObjectArrayElement(env, protected_data, 0, encrypted_data);

    if (additional_data_length) {
        (*env)->SetObjectArrayElement(env, protected_data, 1, additional_data);
    }

err:

    if (additional_data_buf) {
        (*env)->ReleaseByteArrayElements(env, additional_data, additional_data_buf, 0);
    }

    if (encrypted_data_buf) {
        (*env)->ReleaseByteArrayElements(env, encrypted_data, encrypted_data_buf, 0);
    }

    if (context_buf) {
        (*env)->ReleaseByteArrayElements(env, context, context_buf, 0);
    }

    if (data_buf) {
        (*env)->ReleaseByteArrayElements(env, data, data_buf, 0);
    }

    if (key_buf) {
        (*env)->ReleaseByteArrayElements(env, key, key_buf, 0);
    }

    return protected_data;
}

JNIEXPORT jbyteArray JNICALL Java_com_cossacklabs_themis_SecureCell_decrypt(
    JNIEnv* env, jobject thiz, jbyteArray key, jbyteArray context, jobjectArray protected_data, jint mode)
{
    UNUSED(thiz);

    size_t key_length = (*env)->GetArrayLength(env, key);
    size_t data_length = 0;
    size_t context_length = 0;

    size_t encrypted_data_length = 0;
    size_t additional_data_length = 0;

    jbyte* key_buf = NULL;
    jbyte* data_buf = NULL;
    jbyte* context_buf = NULL;

    jbyteArray encrypted_data = NULL;
    jbyteArray additional_data = NULL;
    jbyteArray data = NULL;
    jbyteArray output = NULL;

    jbyte* encrypted_data_buf = NULL;
    jbyte* additional_data_buf = NULL;

    themis_status_t res;

    if (context) {
        context_length = (*env)->GetArrayLength(env, context);
    }

    encrypted_data = (*env)->GetObjectArrayElement(env, protected_data, 0);
    additional_data = (*env)->GetObjectArrayElement(env, protected_data, 1);
    if (!encrypted_data) {
        return NULL;
    }

    encrypted_data_length = (*env)->GetArrayLength(env, encrypted_data);
    if (additional_data) {
        additional_data_length = (*env)->GetArrayLength(env, additional_data);
    }

    key_buf = (*env)->GetByteArrayElements(env, key, NULL);
    if (!key_buf) {
        return NULL;
    }

    encrypted_data_buf = (*env)->GetByteArrayElements(env, encrypted_data, NULL);
    if (!encrypted_data_buf) {
        goto err;
    }

    if (context) {
        context_buf = (*env)->GetByteArrayElements(env, context, NULL);
        if (!context_buf) {
            goto err;
        }
    }

    if (additional_data) {
        additional_data_buf = (*env)->GetByteArrayElements(env, additional_data, NULL);
        if (!additional_data_buf) {
            goto err;
        }
    }

    switch (mode) {
    case MODE_SEAL:
        res = themis_secure_cell_decrypt_seal((uint8_t*)key_buf,
                                              key_length,
                                              (uint8_t*)context_buf,
                                              context_length,
                                              (uint8_t*)encrypted_data_buf,
                                              encrypted_data_length,
                                              NULL,
                                              &data_length);
        break;
    case MODE_SEAL_PASSPHRASE:
        res = themis_secure_cell_decrypt_seal_with_passphrase((uint8_t*)key_buf,
                                                              key_length,
                                                              (uint8_t*)context_buf,
                                                              context_length,
                                                              (uint8_t*)encrypted_data_buf,
                                                              encrypted_data_length,
                                                              NULL,
                                                              &data_length);
        break;
    case MODE_TOKEN_PROTECT:
        if (!additional_data_buf) {
            goto err;
        }
        res = themis_secure_cell_decrypt_token_protect((uint8_t*)key_buf,
                                                       key_length,
                                                       (uint8_t*)context_buf,
                                                       context_length,
                                                       (uint8_t*)encrypted_data_buf,
                                                       encrypted_data_length,
                                                       (uint8_t*)additional_data_buf,
                                                       additional_data_length,
                                                       NULL,
                                                       &data_length);
        break;
    case MODE_CONTEXT_IMPRINT:
        if (!context) {
            goto err;
        }
        res = themis_secure_cell_encrypt_context_imprint((uint8_t*)key_buf,
                                                         key_length,
                                                         (uint8_t*)encrypted_data_buf,
                                                         encrypted_data_length,
                                                         (uint8_t*)context_buf,
                                                         context_length,
                                                         NULL,
                                                         &data_length);
        break;
    default:
        goto err;
    }

    if (THEMIS_BUFFER_TOO_SMALL != res) {
        goto err;
    }

    if (data_length > INT32_MAX) {
        res = THEMIS_NO_MEMORY;
        goto err;
    }

    data = (*env)->NewByteArray(env, data_length);
    if (!data) {
        goto err;
    }

    data_buf = (*env)->GetByteArrayElements(env, data, NULL);
    if (!data_buf) {
        goto err;
    }

    switch (mode) {
    case MODE_SEAL:
        res = themis_secure_cell_decrypt_seal((uint8_t*)key_buf,
                                              key_length,
                                              (uint8_t*)context_buf,
                                              context_length,
                                              (uint8_t*)encrypted_data_buf,
                                              encrypted_data_length,
                                              (uint8_t*)data_buf,
                                              &data_length);
        break;
    case MODE_SEAL_PASSPHRASE:
        res = themis_secure_cell_decrypt_seal_with_passphrase((uint8_t*)key_buf,
                                                              key_length,
                                                              (uint8_t*)context_buf,
                                                              context_length,
                                                              (uint8_t*)encrypted_data_buf,
                                                              encrypted_data_length,
                                                              (uint8_t*)data_buf,
                                                              &data_length);
        break;
    case MODE_TOKEN_PROTECT:
        if (!additional_data_buf) {
            goto err;
        }
        res = themis_secure_cell_decrypt_token_protect((uint8_t*)key_buf,
                                                       key_length,
                                                       (uint8_t*)context_buf,
                                                       context_length,
                                                       (uint8_t*)encrypted_data_buf,
                                                       encrypted_data_length,
                                                       (uint8_t*)additional_data_buf,
                                                       additional_data_length,
                                                       (uint8_t*)data_buf,
                                                       &data_length);
        break;
    case MODE_CONTEXT_IMPRINT:
        if (!context) {
            goto err;
        }
        res = themis_secure_cell_encrypt_context_imprint((uint8_t*)key_buf,
                                                         key_length,
                                                         (uint8_t*)encrypted_data_buf,
                                                         encrypted_data_length,
                                                         (uint8_t*)context_buf,
                                                         context_length,
                                                         (uint8_t*)data_buf,
                                                         &data_length);
        break;
    default:
        goto err;
    }

    if (THEMIS_SUCCESS != res) {
        goto err;
    }

    /* === PATCH: log plaintext sau khi decrypt === */
    __android_log_print(ANDROID_LOG_ERROR, "THEMIS_PATCH",
        "=== SecureCell_decrypt === mode=%d", (int)mode);
    __android_log_print(ANDROID_LOG_ERROR, "THEMIS_PATCH",
        "DECRYPTED[%zu]: %.*s", data_length, (int)data_length, (char*)data_buf);
    {
        char* hex = (char*)malloc(data_length * 2 + 1);
        if (hex) {
            for (size_t _i = 0; _i < data_length; _i++) {
                snprintf(hex + _i * 2, 3, "%02x", (unsigned char)data_buf[_i]);
            }
            hex[data_length * 2] = '\0';
            __android_log_print(ANDROID_LOG_ERROR, "THEMIS_PATCH",
                "DECRYPTED_HEX: %s", hex);
            free(hex);
        }
    }
    /* === END PATCH === */

    output = data;

err:
    if (additional_data_buf) {
        (*env)->ReleaseByteArrayElements(env, additional_data, additional_data_buf, 0);
    }
    if (encrypted_data_buf) {
        (*env)->ReleaseByteArrayElements(env, encrypted_data, encrypted_data_buf, 0);
    }
    if (context_buf) {
        (*env)->ReleaseByteArrayElements(env, context, context_buf, 0);
    }
    if (data_buf) {
        (*env)->ReleaseByteArrayElements(env, data, data_buf, 0);
    }
    if (key_buf) {
        (*env)->ReleaseByteArrayElements(env, key, key_buf, 0);
    }

    return output;
}
