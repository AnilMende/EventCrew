import { connectToDatabase } from "@/lib/db/mongodb";
import { loginSchema } from "@/lib/validations/auth";
import { RefreshSessionModel } from "@/models/RefreshSession";
import { UserModel } from "@/models/User";
import bcrypt from "bcryptjs";
import { createHash, randomUUID } from "crypto";
import { SignJWT } from "jose";
import { NextRequest, NextResponse } from "next/server";


const ACCESS_TOKEN_TTL = 15 * 60;
const REFRESH_TOKEN_TTL = 7 * 24 * 60 * 60;

export const POST = async (request: NextRequest) => {

    try {
        // parse the request body
        let body: unknown;

        try {

            body = await request.json();

        } catch {
            return NextResponse.json(
                { success: false, message: "Invalid JSON request body" },
                { status: 400 }
            );
        }

        // validate the input
        const result = loginSchema.safeParse(body);

        if (!result.success) {
            return NextResponse.json(
                {
                    success: false,
                    message: "Validation failed",
                    errors: result.error.flatten().fieldErrors,
                },
                { status: 400 }
            );
        }

        const { email, password } = result.data;

        // bcrypt only processes up to 72 password bytes
        if (Buffer.byteLength(password, "utf8") > 72) {
            return NextResponse.json(
                { success: false, message: "Invalid email or password" },
                { status: 401 }
            );
        }

        // connect to database
        await connectToDatabase();

        // Explicitly select passwordHash because the model hides it by default
        const user = await UserModel.findOne({ email }).select("+passwordHash");

        // verify the credentials using the stored password hash
        if (!user) {
            return NextResponse.json(
                { success: false, message: "Invalid email or password" },
                { status: 401 }
            );
        }

        // compare the password
        const passwordMatches = await bcrypt.compare(password, user.passwordHash);

        if (!passwordMatches || !user.isActive) {
            return NextResponse.json(
                { success: false, message: "Invalid email or password" },
                { status: 401 }
            );
        }

        // read secrets only on the server
        const accessSecret = process.env.ACCESS_TOKEN_SECRET;
        const refreshSecret = process.env.REFRESH_TOKEN_SECRET;

        if (!accessSecret || !refreshSecret) {
            throw new Error("Authentication secrets are not configured");
        }

        const accessKey = new TextEncoder().encode(accessSecret);
        const refreshKey = new TextEncoder().encode(refreshSecret);

        // create a short-lived access token
        const accessToken = await new SignJWT({
            role: user.role,
            tokenType: "access"
        })
            .setProtectedHeader({ alg: "HS256" })
            .setSubject(user._id.toString())
            .setIssuer("eventcrew")
            .setAudience("eventcrew")
            .setIssuedAt()
            .setExpirationTime("15m")
            .sign(accessKey);

        // create a long lived refresh token


        const sessionId = randomUUID();

        const refreshToken = await new SignJWT({
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


        const tokenHash = createHash("sha256")
            .update(refreshToken)
            .digest("hex");

        await RefreshSessionModel.create({
            userId: user._id.toString(),
            sessionId,
            tokenHash,
            expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL * 1000),
            revokedAt: null
        });

        // Return a safe user object and set HTTP-only cookies
        const response = NextResponse.json(
            {
                success: true,
                message: "Login sucessful",
                user: {
                    id: user._id.toString(),
                    name: user.name,
                    email: user.email,
                    role: user.role,
                    isEmailVerified: user.isEmailVerified
                }
            },
            { status: 200 }
        );


        response.cookies.set("eventcrew_access", accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            path: "/",
            maxAge: ACCESS_TOKEN_TTL,
        });

        response.cookies.set("eventcrew_refresh", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            path: "/api/auth",
            maxAge: REFRESH_TOKEN_TTL
        });

        return response;


    } catch (error: unknown) {
        console.error("Login failed:", error);

        return NextResponse.json(
            { success: false, message: "Unable to log in" },
            { status: 500 }
        );
    }
}