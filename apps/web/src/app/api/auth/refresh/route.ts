import { connectToDatabase } from "@/lib/db/mongodb";
import { RefreshSessionModel } from "@/models/RefreshSession";
import { UserModel } from "@/models/User";
import { createHash, randomUUID } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";
import { NextRequest, NextResponse } from "next/server";


const ACCESS_TOKEN_TTL = 15 * 60;
const REFRESH_TOKEN_TTL = 7 * 24 * 60 * 60;

const clearAuthCookies = (response: NextResponse) => {

    response.cookies.set("eventcrew_access", "", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: 0
    });

    response.cookies.set("eventcrew_refresh", "", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/api/auth",
        maxAge: 0
    });

    return response;
}

const unauthorized = () =>
    clearAuthCookies(
        NextResponse.json(
            { success: false, message: "Invalid or expired session" },
            { status: 401 }
        )
    );

export const POST = async (request: NextRequest) => {

    try {
        console.log("[REFRESH] Route handler reached");

        const refreshToken = request.cookies.get("eventcrew_refresh")?.value;

        console.log("[REFRESH] Cookie received:", Boolean(refreshToken));

        if (!refreshToken) {
            return unauthorized();
        }

        const refreshSecret = process.env.REFRESH_TOKEN_SECRET;
        const accessSecret = process.env.ACCESS_TOKEN_SECRET;

        if (!refreshSecret || !accessSecret) {
            throw new Error("Authentication secrets are not configured");
        }

        // verify the tokens signature and standard class
        const refreshKey = new TextEncoder().encode(refreshSecret);

        let payload;

        try {
            const verified = await jwtVerify(refreshToken, refreshKey, {
                issuer: "eventcrew",
                audience: "eventcrew",
                algorithms: ["HS256"]
            });

            payload = verified.payload;

        } catch (error) {
            console.error("Refresh JWT verification failed:", error);
            return unauthorized();
        }


        // validate the tokens purpose and identifiers
        const userId = payload.sub;
        const sessionId = payload.sid;

        console.log("[REFRESH] Claim check:", {
            tokenType: payload.tokenType,
            hasSubject: typeof userId === "string",
            hasSessionId: typeof sessionId === "string",
            hasTokenId: typeof payload.jti === "string",
        });

        if (
            payload.tokenType !== "refresh" ||
            typeof userId !== "string" ||
            typeof sessionId !== "string" ||
            typeof payload.jti !== "string"
        ) {
            console.error("[REFRESH] Token claim validation failed");
            return unauthorized();
        }

        await connectToDatabase();

        const now = new Date();

        const presentedHash = createHash("sha256")
            .update(refreshToken)
            .digest("hex");

        // create replacement tokens for this same session
        const user = await UserModel.findById(userId);

        if (!user || !user.isActive) {
            await RefreshSessionModel.updateOne(
                { sessionId, userId, revokedAt: null },
                { $set: { revokedAt: now } }
            );

            return unauthorized();
        }

        const accessKey = new TextEncoder().encode(accessSecret);

        const accessToken = await new SignJWT({
            role: user.role,
            tokenType: "access",
        })
            .setProtectedHeader({ alg: "HS256" })
            .setSubject(user._id.toString())
            .setIssuer("eventcrew")
            .setAudience("eventcrew")
            .setIssuedAt()
            .setExpirationTime("15m")
            .sign(accessKey);

        const nextRefreshToken = await new SignJWT({
            tokenType: "refresh",
            sid: sessionId,
        })
            .setProtectedHeader({ alg: "HS256" })
            .setSubject(user._id.toString())
            .setJti(randomUUID())
            .setIssuer("eventcrew")
            .setAudience("eventcrew")
            .setIssuedAt()
            .setExpirationTime("7d")
            .sign(refreshKey);

        const nextHash = createHash("sha256")
            .update(nextRefreshToken)
            .digest("hex");

        // 4. Atomically replace the current token hash.
        // Only one request using this token can win.
        const rotatedSession =
            await RefreshSessionModel.findOneAndUpdate(
                {
                    sessionId,
                    userId: user._id,
                    tokenHash: presentedHash,
                    revokedAt: null,
                    expiresAt: { $gt: now },
                },
                {
                    $set: {
                        tokenHash: nextHash,
                        expiresAt: new Date(
                            now.getTime() + REFRESH_TOKEN_TTL * 1000
                        ),
                    },
                },
                { returnDocument : "after" }
            );

        if (!rotatedSession) {
            // A previously valid token that no longer matches the
            // stored hash may have been reused after rotation.
            const session = await RefreshSessionModel.findOne({
                sessionId,
                userId: user._id,
            });

            if (
                session &&
                !session.revokedAt &&
                session.expiresAt > now &&
                session.tokenHash !== presentedHash
            ) {
                await RefreshSessionModel.updateOne(
                    {
                        sessionId,
                        userId: user._id,
                        tokenHash: session.tokenHash,
                        revokedAt: null,
                    },
                    { $set: { revokedAt: now } }
                );
            }

            return unauthorized();
        }

        // 5. Return the new access token and rotated refresh token
        const response = NextResponse.json({
            success: true,
            message: "Session refreshed successfully",
            user: {
                id: user._id.toString(),
                name: user.name,
                email: user.email,
                role: user.role,
                isEmailVerified: user.isEmailVerified,
            },
        });

        response.cookies.set("eventcrew_access", accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            path: "/",
            maxAge: ACCESS_TOKEN_TTL,
        });

        response.cookies.set("eventcrew_refresh", nextRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            path: "/api/auth",
            maxAge: REFRESH_TOKEN_TTL,
        });

        return response;

    } catch (error: unknown) {
        console.error("Token refresh failed:", error);

        return NextResponse.json(
            { success: false, message: "Unable to refresh session" },
            { status: 500 }
        );
    }
}