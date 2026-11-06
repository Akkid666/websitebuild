
import bcrypt from "bcryptjs";
import { getDb } from "../lib/db.js";
import { createSession, setSessionCookie } from "../lib/auth.js";

export default async function handler(req, res) {
    if (req.method !== "POST") {
        return res.status(405).json({ error: "Method not allowed" });
    }

    try {
        const { email, password } = req.body || {};

        if (typeof email !== "string" ||
            typeof password !== "string" ||
            email.length > 255 ||
            password.length > 72) {
            return res.status(400).json({
                error: "Ogiltiga inloggningsuppgifter."
            });
        }

        const cleanEmail = email.trim().toLowerCase();
        const db = getDb();

        const users = await db`
            SELECT id, username, email, password_hash
            FROM users
            WHERE email = ${cleanEmail}
            LIMIT 1
        `;

        if (!users.length) {
            return res.status(401).json({
                error: "Fel e-postadress eller lösenord."
            });
        }

        const user = users[0];
        const valid = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!valid) {
            return res.status(401).json({
                error: "Fel e-postadress eller lösenord."
            });
        }

        const token = await createSession(user);
        setSessionCookie(res, token);

        return res.status(200).json({
            success: true,
            user: {
                username: user.username,
                email: user.email
            }
        });

    } catch (error) {
        console.error("Login error:", error.message);

        return res.status(500).json({
            error: "Inloggningen misslyckades."
        });
    }
}
