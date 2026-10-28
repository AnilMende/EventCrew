import { NextRequest, NextResponse } from "next/server";
import { createHash } from "node:crypto";
import { jwtVerify } from "jose";
import { connectToDatabase } from "@/lib/db/mongodb";
import { RefreshSessionModel } from "@/models/RefreshSession";


const clearAuthCookies = (response: NextResponse) => {
    response.cookies.set("eventcrew_access", "", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: 0,
    });

    response.cookies.set("eventcrew_refresh", "", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/api/auth",
        maxAge: 0,
    });

    return response;
};

export const POST = async (request: NextRequest) => {

    try {

        const response = NextResponse.json({
            success: true,
            message: "Logged out successfully"
        });

        const refreshToken = request.cookies.get("eventcrew_refresh")?.value;

        if (!refreshToken) {
            return clearAuthCookies(response);
        }

        const refreshSecret = process.env.REFRESH_TOKEN_SECRET;

        if (!refreshSecret) {
            throw new Error("Refresh token secret is not configured");
        }

        let payload;

        try {
            const verified = await jwtVerify(
                refreshToken,
                new TextEncoder().encode(refreshSecret),
                {
                    issuer: "eventcrew",
                    audience: "eventcrew",
                    algorithms: ["HS256"],
                }
            );

            payload = verified.payload;
        } catch {
            // Invalid or expired token: clear cookies without trusting its claims.
            return clearAuthCookies(response);
        }

        const userId = payload.sub;
        const sessionId = payload.sid;

        if (
            payload.tokenType !== "refresh" ||
            typeof userId !== "string" ||
            typeof sessionId !== "string" ||
            typeof payload.jti !== "string"
        ) {
            return clearAuthCookies(response);
        }

        await connectToDatabase();

        const presentedHash = createHash("sha256")
            .update(refreshToken)
            .digest("hex");

        await RefreshSessionModel.updateOne(
            {
                sessionId,
                userId,
                tokenHash: presentedHash,
                revokedAt: null,
            },
            {
                $set: { revokedAt: new Date() },
            }
        );

        return clearAuthCookies(response);

    } catch (error: unknown) {
        
        console.error("Logout failed:", error);

        return NextResponse.json(
            {
                success: false,
                message: "Unable to log out",
            },
            { status: 500 }
        );
    }

}