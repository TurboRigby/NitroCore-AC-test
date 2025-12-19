import {Buffer} from "node:buffer"
import {useLogger} from "~/utils/useLogger"

export type LiveLinkVersionName = string
export type LiveLinkHashKey = string

/**
 * Map<VersionName, HashKey>
 *
 * HashKey is expected to be the SHA256 of the game binary (32 bytes),
 * encoded as either:
 * - 64-char hex string (recommended), or
 * - base64/base64url for 32 raw bytes
 *
 * Populate this with known-clean hashes for each supported Geometry Dash version.
 */
export const LIVE_LINK_HASH_KEYS = new Map<LiveLinkVersionName, LiveLinkHashKey>([
    // ["gd-2.206", "0123... (64 hex chars)"],
])

export type LiveLinkKeyringEntry = {
    version: LiveLinkVersionName
    key: Buffer // 32 bytes
}

const isHexSha256 = (value: string) => /^[0-9a-f]{64}$/i.test(value)

const decodeBase64Like = (value: string) => {
    const trimmed = value.trim()
    const isBase64Url = /[-_]/.test(trimmed) && !/[+/]/.test(trimmed)
    return Buffer.from(trimmed, isBase64Url ? "base64url" : "base64")
}

export const useLiveLinkKeys = () => {
    const parseKey = (value: string) => {
        if (isHexSha256(value)) {
            return Buffer.from(value, "hex")
        }

        const decoded = decodeBase64Like(value)
        if (decoded.byteLength !== 32) {
            throw new Error("Invalid key length (expected 32 bytes)")
        }
        return decoded
    }

    const loadFromEnv = () => {
        const raw = process.env.LIVE_LINK_HASH_KEYS_JSON
        if (!raw) {
            return new Map<LiveLinkVersionName, LiveLinkHashKey>()
        }

        const parsed = JSON.parse(raw) as unknown
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
            throw new Error("LIVE_LINK_HASH_KEYS_JSON must be a JSON object")
        }

        return new Map(Object.entries(parsed as Record<string, string>))
    }

    const buildKeyring = () => {
        const merged = new Map(LIVE_LINK_HASH_KEYS)
        for (const [version, key] of loadFromEnv()) {
            merged.set(version, key)
        }

        const keyring: LiveLinkKeyringEntry[] = []
        for (const [version, key] of merged) {
            try {
                const parsedKey = parseKey(key)
                if (parsedKey.byteLength !== 32) {
                    throw new Error("Invalid key length (expected 32 bytes)")
                }
                keyring.push({version, key: parsedKey})
            } catch (error) {
                useLogger().error(`[live-link] Invalid hash key for "${version}": ${(error as Error).message}`)
            }
        }

        return keyring
    }

    return {
        buildKeyring,
    }
}
