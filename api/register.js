
import bcrypt from "bcryptjs";
import { getDb } from "../lib/db.js";
import { createSession, setSessionCookie } from "../lib/auth.js";

export default async function handler(req, res) {
    if (req.method !== "POST") {
        return res.status(405).json({ error: "Method not allowed" });
    }

    try {
        const { username, email, password } = req.body || {};

        const cleanUsername = String(username || "").trim();
        const cleanEmail = String(email || "").trim().toLowerCase();

        if (!/^[a-zA-Z0-9_]{3,24}$/.test(cleanUsername)) {
            return res.status(400).json({
                error: "Användarnamnet måste vara 3–24 tecken."
            });
        }

        if (cleanEmail.length > 255 ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
            return res.status(400).json({
                error: "Ogiltig e-postadress."
            });
        }

        if (typeof password !== "string" || password.length < 8 ||
            Buffer.byteLength(password, "utf8") > 72) {
            return res.status(400).json({
                error: "Lösenordet måste vara minst 8 tecken."
            });
        }

        const db = getDb();
        const passwordHash = await bcrypt.hash(password, 12);

        const users = await db`
            INSERT INTO users (username, email, password_hash)
            VALUES (${cleanUsername}, ${cleanEmail}, ${passwordHash})
            RETURNING id, username, email
        `;

        const user = users[0];
        const token = await createSession(user);

        setSessionCookie(res, token);

        return res.status(201).json({
            success: true,
            user: {
                username: user.username,
                email: user.email
            }
        });

    } catch (error) {
        if (error.code === "23505") {
            return res.status(409).json({
                error: "E-postadressen används redan."
            });
        }

        console.error("Registration error:", error.message);

        return res.status(500).json({
            error: "Kunde inte skapa kontot."
        });
    }
}
