import {randomBytes, timingSafeEqual} from "node:crypto"
import {Buffer} from "node:buffer"
import {z} from "zod"
import {useLiveLinkCrypto, LiveLinkAuthPayloadSchema} from "~/utils/useLiveLinkCrypto"
import {useLiveLinkKeys} from "~/utils/useLiveLinkKeys"
import {useLiveLinkSessions, type LiveLinkSession} from "~/utils/useLiveLinkSessions"

/**
 * Client message formats (suggested):
 *
 * 1) Auth response (AES-256-GCM recommended):
 * {
 *   "cmd": "auth_response",
 *   "payload": {
 *     "alg": "aes-256-gcm",
 *     "iv":  "<base64|base64url>",
 *     "tag": "<base64|base64url>",
 *     "data": "<base64|base64url>"
 *   }
 * }
 * Where decrypted JSON MUST contain `{ "nonce": "<challenge nonce>" }`.
 *
 * 2) Telemetry:
 * { "seq": 1, "frames": [...], "current_pct": 10 }
 */

const readNumberEnv = (name: string, fallback: number) => {
    const raw = process.env[name]
    if (!raw) {
        return fallback
    }
    const value = Number(raw)
    return Number.isFinite(value) ? value : fallback
}

const LIVE_LINK_CONFIG = {
    handshakeTimeoutMs: readNumberEnv("LIVE_LINK_HANDSHAKE_TIMEOUT_MS", 5_000),
    maxMessageBytes: readNumberEnv("LIVE_LINK_MAX_MESSAGE_BYTES", 256 * 1024),
    maxFramesPerChunk: readNumberEnv("LIVE_LINK_MAX_FRAMES_PER_CHUNK", 600),
    maxPctPerSecond: readNumberEnv("LIVE_LINK_MAX_PCT_PER_SECOND", 20),
    maxPctBurst: readNumberEnv("LIVE_LINK_MAX_PCT_BURST", 5),
    maxAbsCoord: readNumberEnv("LIVE_LINK_MAX_ABS_COORD", 10_000_000),
    maxCoordDelta: readNumberEnv("LIVE_LINK_MAX_COORD_DELTA", 20_000),
}

const sendJson = (peer: LiveLinkSession["peer"], payload: unknown) => peer.send(JSON.stringify(payload))

const closeUnauthorized = (peer: LiveLinkSession["peer"], reason: string) => {
    try {
        peer.close(1008, reason) // Policy Violation
    } catch {
        peer.terminate()
    }
}

const killAndClose = (peer: LiveLinkSession["peer"], reason: string) => {
    sendJson(peer, {cmd: "kill"})
    closeUnauthorized(peer, reason)
}

const keyring = useLiveLinkKeys().buildKeyring()
const crypto = useLiveLinkCrypto()

const TelemetrySchema = z.object({
    cmd: z.literal("telemetry").optional(),
    seq: z.number().int().nonnegative(),
    current_pct: z.number().finite(),
    frames: z.array(z.unknown()),
}).passthrough()

type TelemetryMessage = z.infer<typeof TelemetrySchema>

const timingSafeEqualString = (a: string, b: string) => {
    const aBuf = Buffer.from(a)
    const bBuf = Buffer.from(b)
    if (aBuf.byteLength !== bBuf.byteLength) {
        return false
    }
    return timingSafeEqual(aBuf, bBuf)
}

export default defineWebSocketHandler({
    open(peer) {
        const sessions = useLiveLinkSessions()

        const nonce = randomBytes(32).toString("base64url")
        peer.context.liveLink = {
            nonce,
            authorized: false,
        }

        const session: LiveLinkSession = {
            id: peer.id,
            remoteAddress: peer.remoteAddress,
            createdAt: Date.now(),
            auth: {
                state: "challenging",
                nonce,
                handshakeTimer: setTimeout(() => {
                    if (session.auth.state !== "authorized") {
                        closeUnauthorized(peer, "Auth timeout")
                    }
                }, LIVE_LINK_CONFIG.handshakeTimeoutMs),
            },
            telemetry: {
                expectedSeq: 1,
            },
            peer,
        }

        sessions.set(peer.id, session)

        if (keyring.length === 0) {
            useLogger().error("[live-link] No LIVE_LINK_HASH_KEYS configured; rejecting connection")
            closeUnauthorized(peer, "Server misconfigured")
            return
        }

        sendJson(peer, {cmd: "auth_challenge", nonce})
    },

    message(peer, message) {
        const sessions = useLiveLinkSessions()
        const session = sessions.get(peer.id)
        if (!session) {
            closeUnauthorized(peer, "No session")
            return
        }

        const size = message.uint8Array().byteLength
        if (size > LIVE_LINK_CONFIG.maxMessageBytes) {
            killAndClose(peer, "Message too large")
            return
        }

        let data: unknown
        try {
            data = message.json()
        } catch {
            killAndClose(peer, "Invalid JSON")
            return
        }

        if (data && typeof data === "object" && (data as any).cmd === "ping") {
            sendJson(peer, {cmd: "pong", t: Date.now()})
            return
        }

        if (session.auth.state !== "authorized") {
            const envelopeCandidate =
                data && typeof data === "object" && "payload" in (data as Record<string, unknown>)
                    ? (data as any).payload
                    : data

            let envelope: ReturnType<typeof crypto.parseAuthEnvelope>
            try {
                envelope = crypto.parseAuthEnvelope(envelopeCandidate)
            } catch {
                closeUnauthorized(peer, "Bad auth envelope")
                return
            }

            let authedVersion: string | undefined
            let authPayload: z.infer<typeof LiveLinkAuthPayloadSchema> | undefined

            for (const {version, key} of keyring) {
                try {
                    const plaintext = crypto.decryptAuthEnvelope(envelope, key)
                    const parsed = LiveLinkAuthPayloadSchema.parse(JSON.parse(plaintext))

                    if (!timingSafeEqualString(parsed.nonce, session.auth.nonce)) {
                        // Decrypted with a valid key, but nonce doesn't match our challenge => replay/desync.
                        closeUnauthorized(peer, "Nonce mismatch")
                        return
                    }

                    authedVersion = version
                    authPayload = parsed
                    break
                } catch {
                    // wrong key / auth tag mismatch / padding error / invalid JSON
                    continue
                }
            }

            if (!authedVersion || !authPayload) {
                closeUnauthorized(peer, "Unauthorized")
                return
            }

            session.auth.state = "authorized"
            session.auth.version = authedVersion
            const liveLinkContext = peer.context.liveLink as any
            if (liveLinkContext && typeof liveLinkContext === "object") {
                liveLinkContext.authorized = true
            }
            if (session.auth.handshakeTimer) {
                clearTimeout(session.auth.handshakeTimer)
                session.auth.handshakeTimer = undefined
            }

            sendJson(peer, {
                cmd: "auth_ok",
                version: authedVersion,
            })
            return
        }

        let telemetry: TelemetryMessage
        try {
            telemetry = TelemetrySchema.parse(data)
        } catch {
            killAndClose(peer, "Bad telemetry")
            return
        }

        if (telemetry.seq !== session.telemetry.expectedSeq) {
            killAndClose(peer, "Sequence mismatch")
            return
        }

        session.telemetry.expectedSeq++

        const now = Date.now()
        const lastAt = session.telemetry.lastAt
        const lastPct = session.telemetry.lastPct

        if (lastAt !== undefined && lastPct !== undefined) {
            const dtSec = (now - lastAt) / 1000
            if (dtSec <= 0) {
                killAndClose(peer, "Invalid time delta")
                return
            }

            const deltaPct = telemetry.current_pct - lastPct

            // Percent can legitimately drop if the player dies/restarts. Treat as a reset baseline.
            if (deltaPct >= 0) {
                const maxAllowed = LIVE_LINK_CONFIG.maxPctBurst + LIVE_LINK_CONFIG.maxPctPerSecond * dtSec
                if (deltaPct > maxAllowed) {
                    killAndClose(peer, "Speedhack (pct jump)")
                    return
                }
            }
        }

        session.telemetry.lastAt = now
        session.telemetry.lastPct = telemetry.current_pct

        if (telemetry.frames.length > LIVE_LINK_CONFIG.maxFramesPerChunk) {
            killAndClose(peer, "Too many frames")
            return
        }

        for (const frame of telemetry.frames) {
            if (!frame || typeof frame !== "object") {
                continue
            }

            // Client-side mod suggestion: include `x` and `y` per frame (or per N frames) for sanity checks.
            const x = (frame as any).x
            const y = (frame as any).y
            if (x === undefined || y === undefined) {
                continue
            }

            if (typeof x !== "number" || typeof y !== "number" || !Number.isFinite(x) || !Number.isFinite(y)) {
                killAndClose(peer, "Invalid coordinates")
                return
            }

            if (Math.abs(x) > LIVE_LINK_CONFIG.maxAbsCoord || Math.abs(y) > LIVE_LINK_CONFIG.maxAbsCoord) {
                killAndClose(peer, "Impossible coordinates")
                return
            }

            const lastCoord = session.telemetry.lastCoord
            if (lastCoord) {
                const dx = Math.abs(x - lastCoord.x)
                const dy = Math.abs(y - lastCoord.y)

                // Basic noclip/speed sanity: impossible per-frame delta.
                // TODO: Replace with GD-accurate physics validation:
                // - validate jump trajectories / gravity flips
                // - validate collision hits vs. level geometry
                // - validate portal/orb trigger ordering
                if (dx > LIVE_LINK_CONFIG.maxCoordDelta || dy > LIVE_LINK_CONFIG.maxCoordDelta) {
                    killAndClose(peer, "Impossible movement")
                    return
                }
            }

            session.telemetry.lastCoord = {x, y}
        }
    },

    close(peer) {
        const sessions = useLiveLinkSessions()
        const session = sessions.get(peer.id)
        if (!session) {
            return
        }

        if (session.auth.handshakeTimer) {
            clearTimeout(session.auth.handshakeTimer)
        }

        sessions.delete(peer.id)
    },

    error(peer, error) {
        useLogger().error(`[live-link] ws error (${peer.id}): ${error.message}`)
    },
})
