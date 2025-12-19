import {createDecipheriv} from "node:crypto"
import {Buffer} from "node:buffer"
import {z} from "zod"

const AuthEnvelopeSchema = z.object({
    iv: z.string().min(1),
    data: z.string().min(1).optional(),
    ciphertext: z.string().min(1).optional(),
    tag: z.string().min(1).optional(),
    alg: z.string().optional(),
}).passthrough()

export type LiveLinkAuthEnvelope = z.infer<typeof AuthEnvelopeSchema>

export const LiveLinkAuthPayloadSchema = z.object({
    nonce: z.string().min(1),
}).passthrough()

export type LiveLinkAuthPayload = z.infer<typeof LiveLinkAuthPayloadSchema>

const decodeBase64Like = (value: string) => {
    const trimmed = value.trim()
    const isBase64Url = /[-_]/.test(trimmed) && !/[+/]/.test(trimmed)
    return Buffer.from(trimmed, isBase64Url ? "base64url" : "base64")
}

const decryptAes256Gcm = (key: Buffer, iv: Buffer, ciphertext: Buffer, tag: Buffer) => {
    const decipher = createDecipheriv("aes-256-gcm", key, iv)
    decipher.setAuthTag(tag)
    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

const decryptAes256Cbc = (key: Buffer, iv: Buffer, ciphertext: Buffer) => {
    const decipher = createDecipheriv("aes-256-cbc", key, iv)
    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

export const useLiveLinkCrypto = () => {
    const parseAuthEnvelope = (message: unknown): LiveLinkAuthEnvelope => AuthEnvelopeSchema.parse(message)

    const decryptAuthEnvelope = (envelope: LiveLinkAuthEnvelope, key: Buffer) => {
        const ciphertextBase64 = envelope.data ?? envelope.ciphertext
        if (!ciphertextBase64) {
            throw new Error("Missing ciphertext (expected 'data' or 'ciphertext')")
        }

        const iv = decodeBase64Like(envelope.iv)
        const ciphertext = decodeBase64Like(ciphertextBase64)

        const alg = (envelope.alg || "").toLowerCase()
        const wantsGcm = Boolean(envelope.tag) || alg.includes("gcm")

        if (wantsGcm) {
            const tag = envelope.tag ? decodeBase64Like(envelope.tag) : Buffer.alloc(0)
            if (tag.byteLength !== 16) {
                throw new Error("Invalid GCM tag length (expected 16 bytes)")
            }
            if (iv.byteLength < 12 || iv.byteLength > 32) {
                throw new Error("Invalid GCM IV length (expected 12-32 bytes)")
            }
            return decryptAes256Gcm(key, iv, ciphertext, tag).toString("utf8")
        }

        if (iv.byteLength !== 16) {
            throw new Error("Invalid CBC IV length (expected 16 bytes)")
        }

        return decryptAes256Cbc(key, iv, ciphertext).toString("utf8")
    }

    return {
        parseAuthEnvelope,
        decryptAuthEnvelope,
    }
}

