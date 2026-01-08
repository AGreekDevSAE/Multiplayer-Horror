const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const net = require("net");
const crypto = require("crypto");

const admin = require("firebase-admin");
const bcrypt = require("bcryptjs");
const fs = require("fs");


const app = express();

app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT) || 8080;

//#region CONFIG
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
//#endregion

//#region DB TABLE/COLUMN NAMES
const room_list_T = "rooms";
const id_column = "id";
const room_name_column = "room_name";
const ip_column = "ip";
const port_column = "port";
const max_players_column = "max_players";
//#endregion


const serviceAccountPath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH || "";

if (!serviceAccountPath)
{
    throw new Error("Missing FIREBASE_SERVICE_ACCOUNT_PATH");
}

const serviceAccountRaw = fs.readFileSync(serviceAccountPath, "utf8");
const serviceAccount = JSON.parse(serviceAccountRaw);

admin.initializeApp(
{
    credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();



function checkConnection(host, port, timeout = 10000)
{
    return new Promise((resolve, reject) =>
    {
        let socket;
        const timer = setTimeout(() =>
        {
            reject(new Error(`Timeout trying to connect to host ${host}, port ${port}`));
            if (socket)
            {
                socket.end();
            }
        }, timeout);

        socket = net.connect({ port: port, host: host }, () =>
        {
            clearTimeout(timer);
            resolve();
            socket.end();
        });

        socket.on("error", (err) =>
        {
            clearTimeout(timer);
            reject(err);
        });

        socket.unref();
    });
}

function generateToken(payload)
{
    return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });
}

function authenticate(req, res, next)
{
    const authHeader = req.headers.authorization;

    if (!authHeader)
    {
        return res.status(401).json({ error: "Missing token" });
    }

    const parts = authHeader.split(" ");
    const token = parts.length === 2 ? parts[1] : null;

    if (!token)
    {
        return res.status(401).json({ error: "Missing token" });
    }

    try
    {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    }
    catch
    {
        return res.status(401).json({ error: "Invalid token" });
    }
}


//#region helpers
function usersCol()
{
    return db.collection("users");
}

function scoresCol()
{
    return db.collection("scores");
}

function roomsCol()
{
    return db.collection("rooms");
}

async function findUserByEmail(email)
{
    const snap = await usersCol().where("email", "==", email).limit(1).get();

    if (snap.empty)
    {
        return null;
    }

    const doc = snap.docs[0];
    return { id: doc.id, ...doc.data() };
}
//#endregion

//#region AUTH
app.post("/auth/register", async (req, res) =>
{
    try
    {
        const { email, username, password } = req.body;

        if (!email || !username || !password)
        {
            return res.status(400).json({ error: "Invalid payload" });
        }

        const existing = await findUserByEmail(email);
        if (existing)
        {
            return res.status(409).json({ error: "Email already registered" });
        }

        const userId = crypto.randomUUID();
        const passwordHash = await bcrypt.hash(password, 10);

        await usersCol().doc(userId).set(
        {
            email,
            username,
            passwordHash,
            totalMatches: 0,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        const token = generateToken({ userId });

        res.json({ token });
    }
    catch
    {
        res.status(500).json({ error: "Server error" });
    }
});


app.post("/auth/login", async (req, res) =>
{
    try
    {
        const { email, password } = req.body;

        if (!email || !password)
        {
            return res.status(400).json({ error: "Invalid payload" });
        }

        const user = await findUserByEmail(email);
        if (!user)
        {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const ok = await bcrypt.compare(password, user.passwordHash || "");
        if (!ok)
        {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = generateToken({ userId: user.id });

        res.json({ token });
    }
    catch
    {
        res.status(500).json({ error: "Server error" });
    }
});


app.get("/profile/me", authenticate, async (req, res) =>
{
    try
    {
        const userId = req.user.userId;

        const doc = await usersCol().doc(userId).get();
        if (!doc.exists)
        {
            return res.status(404).json({ error: "User not found" });
        }

        const data = doc.data();

        res.json(
        {
            userId,
            username: data.username || "Player",
            totalMatches: data.totalMatches || 0
        });
    }
    catch
    {
        res.status(500).json({ error: "Server error" });
    }
});

//#endregion

//#region SCORES / LEADERBOARD
app.post("/score", authenticate, async (req, res) =>
{
    try
    {
        const userId = req.user.userId;
        const { score, team, won } = req.body;

        const scoreNumber = Number(score);

        if (!Number.isFinite(scoreNumber) || !team || typeof won !== "boolean")
        {
            return res.status(400).json({ error: "Invalid payload" });
        }

        const scoreId = crypto.randomUUID();

        await scoresCol().doc(scoreId).set(
        {
            userId,
            team,
            score: scoreNumber,
            won,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        await usersCol().doc(userId).update(
        {
            totalMatches: admin.firestore.FieldValue.increment(1)
        });

        res.json({ success: true });
    }
    catch
    {
        res.status(500).json({ error: "Server error" });
    }
});

app.get("/leaderboard", async (req, res) =>
{
    try
    {
        const snap = await scoresCol().orderBy("score", "desc").limit(10).get();

        const rows = snap.docs.map((d) =>
        {
            const data = d.data();
            return { userId: data.userId, score: data.score, team: data.team, won: data.won };
        });

        res.json(rows);
    }
    catch
    {
        res.status(500).json({ error: "Server error" });
    }
});

//#endregion

//#region ROOMS
app.get("/room_list", async (req, res) =>
{
    try
    {
        const snap = await roomsCol().limit(100).get();

        const rooms = snap.docs.map((d) =>
        {
            const data = d.data();
            return { id: d.id, ...data };
        });

        res.status(200).json({ rooms });
    }
    catch
    {
        res.status(500).json({ error: "Server error" });
    }
});


app.post("/room_list/:room_name", async (req, res) =>
{
    const { room_name } = req.params;
    const ip_to_connect = req.body.ip_to_connect;
    const port = req.body.port;
    const max_players = req.body.max_players;

    if (!room_name || !ip_to_connect || port === undefined || max_players === undefined)
    {
        return res.status(400).json({ error: "Invalid payload" });
    }

    try
    {
        await checkConnection(ip_to_connect, port);

        const existing = await roomsCol()
            .where("ip", "==", ip_to_connect)
            .where("port", "==", Number(port))
            .limit(1)
            .get();

        if (!existing.empty)
        {
            return res.status(409).send(`Room already hosted on ${ip_to_connect}:${port}!`);
        }

        const roomId = crypto.randomUUID();

        await roomsCol().doc(roomId).set(
        {
            room_name,
            ip: ip_to_connect,
            port: Number(port),
            max_players: Number(max_players),
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(200).json(
        {
            message: `Room '${room_name}' added successfully!`,
            new_id: roomId,
            ip: ip_to_connect,
            port: Number(port)
        });
    }
    catch (err)
    {
        const msg = err && err.message ? err.message : "Unknown error";
        console.error("Operation Error:", msg);

        if (msg.includes("Timeout") || msg.includes("ECONNREFUSED") || msg.includes("ENOTFOUND"))
        {
            return res.status(404).send(`Address ${ip_to_connect}:${port} not reachable!`);
        }

        res.status(500).send("Internal Server Error during room creation.");
    }
});

//#endregion

app.listen(PORT, () =>
{
    console.log(`Server running on http://localhost:${PORT}`);
});
