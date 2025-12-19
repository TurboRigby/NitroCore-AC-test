import type {Peer} from "crossws"

export type LiveLinkSession = {
    id: string
    remoteAddress?: string
    createdAt: number

    auth: {
        state: "challenging" | "authorized"
        nonce: string
        version?: string
        handshakeTimer?: NodeJS.Timeout
    }

    telemetry: {
        expectedSeq: number
        lastAt?: number
        lastPct?: number
        lastCoord?: {x: number, y: number}
    }

    peer: Peer
}

const GLOBAL_KEY = "__nitrocore_live_link_sessions__"

export const useLiveLinkSessions = () => {
    const globalObj = globalThis as unknown as Record<string, unknown>
    if (!globalObj[GLOBAL_KEY]) {
        globalObj[GLOBAL_KEY] = new Map<string, LiveLinkSession>()
    }
    return globalObj[GLOBAL_KEY] as Map<string, LiveLinkSession>
}

