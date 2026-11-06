
import { getDb } from "../lib/db.js";
import { getSessionToken, verifySession } from "../lib/auth.js";

export default async function handler(req, res) {
    if (req.method !== "GET") {
        return res.status(405).json({ error: "Method not allowed" });
    }

    try {
        const token = getSessionToken(req);

        if (!token) {
            return res.status(401).json({ loggedIn: false });
        }

        const session = await verifySession(token);
        const db = getDb();

        const users = await db`
            SELECT id, username, email
            FROM users
            WHERE id = ${session.id}
            LIMIT 1
        `;

        if (!users.length) {
            return res.status(401).json({ loggedIn: false });
        }

        return res.status(200).json({
            loggedIn: true,
            user: users[0]
        });

    } catch {
        return res.status(401).json({ loggedIn: false });
    }
}
