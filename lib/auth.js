
import { SignJWT, jwtVerify } from "jose";

function getSecret() {
    const value = process.env.SESSION_SECRET;

    if (!value || value.length < 32) {
        throw new Error("SESSION_SECRET must be at least 32 characters");
    }

    return new TextEncoder().encode(value);
}

export async function createSession(user) {
    return await new SignJWT({
        id: user.id,
        email: user.email,
        username: user.username
    })
        .setProtectedHeader({ alg: "HS256" })
        .setIssuedAt()
        .setExpirationTime("7d")
        .sign(getSecret());
}

export async function verifySession(token) {
    const result = await jwtVerify(token, getSecret());
    return result.payload;
}

export function setSessionCookie(res, token) {
    const secure = process.env.NODE_ENV === "production"
        ? "; Secure"
        : "";

    res.setHeader("Set-Cookie",
        `session=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800${secure}`
    );
}

export function clearSessionCookie(res) {
    const secure = process.env.NODE_ENV === "production"
        ? "; Secure"
        : "";

    res.setHeader("Set-Cookie",
        `session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0${secure}`
    );
}

export function getSessionToken(req) {
    const cookies = req.headers.cookie || "";

    const session = cookies
        .split(";")
        .map(item => item.trim())
        .find(item => item.startsWith("session="));

    return session ? decodeURIComponent(session.substring(8)) : null;
}
