const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

require('dotenv').config();
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());
app.use(cors());

// DDoS Protection Shield!
const apiLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 100, // Limit each IP to 100 requests per windowMs
	message: { detail: "Too many requests. Please slow down to protect the server!" },
	standardHeaders: true, 
	legacyHeaders: false, 
});
app.use('/api/', apiLimiter);

// Secret Key for our JWT encryptions (now points securely to .env)
const SECRET_KEY = process.env.SECRET_KEY || "casino-hyper-secret-token";

// --- DATABASE SETUP ---
// Immediately connects to (or builds) custom database file
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) {
        console.error("Database Error:", err.message);
    } else {
        console.log("✅ Successfully connected to SQLite Database.");
    }
});

// Auto-build the Secure Tables the moment the script runs
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT,
            phone_number TEXT,
            password_hash TEXT,
            wallet_balance REAL DEFAULT 0.00
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS mines_games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            bet_amount REAL,
            mines_count INTEGER,
            secret_board TEXT,
            clicked_tiles TEXT,
            status TEXT,
            multiplier REAL DEFAULT 1.0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS memory_games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            bet_amount REAL,
            secret_board TEXT,
            matched_indices TEXT,
            current_flipped INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS flip_games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            bet_amount REAL,
            status TEXT,
            multiplier REAL DEFAULT 1.00,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS chicken_games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            bet_amount REAL,
            difficulty TEXT,
            total_lanes INTEGER,
            secret_path TEXT,
            current_step INTEGER DEFAULT 0,
            status TEXT,
            multiplier REAL DEFAULT 0.00,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS tictactoe_games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            bet_amount REAL,
            difficulty TEXT,
            board TEXT,
            status TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS tower_games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            bet_amount REAL,
            difficulty TEXT,
            cols INTEGER,
            secret_tower TEXT,
            current_row INTEGER DEFAULT 0,
            status TEXT,
            multiplier REAL DEFAULT 0.00,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS memory_games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            bet_amount REAL,
            secret_board TEXT,
            matched_pairs TEXT,
            flipped_indexes TEXT,
            status TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);
});

// --- CASINO GAME ENGINE: MINES ---
const HOUSE_EDGE = 0.99;
function getMultiplier(mines, gemsRevealed) {
    if (gemsRevealed === 0) return 1.0;
    let prob = 1.0;
    let remainingSafe = 25 - mines;
    let remainingTotal = 25;
    for (let i = 0; i < gemsRevealed; i++) {
        prob *= (remainingSafe / remainingTotal);
        remainingSafe--;
        remainingTotal--;
    }
    let multiplier = (1 / prob) * HOUSE_EDGE;
    return Math.floor(multiplier * 100) / 100;
}

// --- API ENDPOINTS ---

// 1. REGISTER
app.post('/api/auth/register/', async (req, res) => {
    const { username, email, phone_number, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ detail: "Username and password required!" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const sql = `INSERT INTO users (username, email, phone_number, password_hash, wallet_balance) VALUES (?, ?, ?, ?, ?)`;
        db.run(sql, [username, email, phone_number, hashedPassword, 0.00], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).json({ detail: "Username already exists!" });
                }
                return res.status(500).json({ detail: "Server error creating user." });
            }
            res.status(201).json({ message: "Registration successful!", user_id: this.lastID });
        });
    } catch (e) {
        res.status(500).json({ detail: "Server encryption error." });
    }
});

// 2. LOGIN
app.post('/api/auth/login/', (req, res) => {
    const { username, password } = req.body;

    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err) {
            return res.status(500).json({ detail: "Database error." });
        }
        if (!user) {
            return res.status(401).json({ detail: "User does not exist." });
        }

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ detail: "Incorrect password." });
        }

        // Issue a digital badge (JWT) locked to this specific user's ID
        const token = jwt.sign({ user_id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '24h' });
        
        res.json({ access: token });
    });
});

// 3. SECURE MIDDLEWARE (Blocks anyone without an access badge)
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1]; // "Bearer TOKEN_HERE"
        jwt.verify(token, SECRET_KEY, (err, decodedUser) => {
            if (err) {
                return res.status(401).json({ detail: "Expired or invalid session." });
            }
            req.user = decodedUser;
            next();
        });
    } else {
        res.status(401).json({ detail: "Not Authorized" });
    }
};

// 4. FETCH WALLET BALANCE
app.get('/api/wallet/', authenticateJWT, (req, res) => {
    db.get(`SELECT wallet_balance FROM users WHERE id = ?`, [req.user.user_id], (err, row) => {
        if (err) {
            return res.status(500).json({ detail: "Error fetching wallet." });
        }
        
        res.json({ wallet_balance: row.wallet_balance });
    });
});

// 4.5 DEPOSIT GATEWAY (Production Ready Mode)
app.post('/api/wallet/deposit/', authenticateJWT, (req, res) => {
    // Currently returns 501 until a real PG (Stripe/UPI) is integrated
    return res.status(501).json({ detail: "Production Payment Gateway not yet connected." });
});

// 5. MINES: START GAME
app.post('/api/games/mines/start/', authenticateJWT, (req, res) => {
    const userId = req.user.user_id;
    const { bet, mines } = req.body;
    
    let betAmount = parseFloat(bet);
    if (isNaN(betAmount) || betAmount < 0) return res.status(400).json({detail: "Invalid bet."});
    if (mines < 1 || mines > 24) return res.status(400).json({detail: "Invalid mines count."});
    
    db.get(`SELECT wallet_balance FROM users WHERE id = ?`, [userId], (err, user) => {
        if (err || !user) return res.status(500).json({detail: "Database error."});
        if (user.wallet_balance < betAmount && betAmount > 0) return res.status(400).json({detail: "Insufficient funds."});
        
        const newBalance = user.wallet_balance - betAmount;
        db.run(`UPDATE users SET wallet_balance = ? WHERE id = ?`, [newBalance, userId], function(err) {
            if (err) return res.status(500).json({detail: "Failed to deduct bet."});
            
            let deck = Array.from({length: 25}, (_, i) => i);
            let bombPositions = [];
            for (let i = 0; i < mines; i++) {
                let r = Math.floor(Math.random() * deck.length);
                bombPositions.push(deck[r]);
                deck.splice(r, 1);
            }
            
            const sql = `INSERT INTO mines_games (user_id, bet_amount, mines_count, secret_board, clicked_tiles, status) VALUES (?, ?, ?, ?, ?, ?)`;
            db.run(sql, [userId, betAmount, mines, JSON.stringify(bombPositions), "[]", "playing"], function(err) {
                if (err) return res.status(500).json({detail: "Failed to save game session."});
                
                // Securely fetch the actual Game ID we just generated
                db.get(`SELECT id FROM mines_games WHERE user_id = ? ORDER BY id DESC LIMIT 1`, [userId], (err, row) => {
                    res.status(200).json({
                        game_id: row.id,
                        wallet_balance: newBalance,
                        status: "playing"
                    });
                });
            });
        });
    });
});

// 6. MINES: CLICK TILE
app.post('/api/games/mines/click/', authenticateJWT, (req, res) => {
    const userId = req.user.user_id;
    const { game_id, tile } = req.body;
    
    db.get(`SELECT * FROM mines_games WHERE id = ? AND user_id = ?`, [game_id, userId], (err, game) => {
        if (err || !game) return res.status(404).json({detail: "Game not found."});
        if (game.status !== "playing") return res.status(400).json({detail: "Game is over."});
        
        let clicked = JSON.parse(game.clicked_tiles || "[]");
        if (clicked.includes(tile)) return res.status(400).json({detail: "Tile already clicked."});
        
        let bombs = JSON.parse(game.secret_board || "[]");
        
        if (bombs.includes(tile)) {
            // EXPLODED BOMB
            db.run(`UPDATE mines_games SET status = 'exploded' WHERE id = ?`, [game.id]);
            return res.status(200).json({ status: "exploded", secret_board: bombs });
        } else {
            // SAFE GEM
            clicked.push(tile);
            const multi = getMultiplier(game.mines_count, clicked.length);
            const isAutoWin = clicked.length === (25 - game.mines_count);
            
            let newStatus = isAutoWin ? 'cashed_out' : 'playing';
            
            db.run(`UPDATE mines_games SET clicked_tiles = ?, multiplier = ?, status = ? WHERE id = ?`, [JSON.stringify(clicked), multi, newStatus, game.id], function(err) {
                if (err) return res.status(500).json({detail: "Failed to record click."});
                
                if (isAutoWin) {
                    const payout = game.bet_amount * multi;
                    db.run(`UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?`, [payout, userId]);
                    return res.status(200).json({
                        status: "cashed_out",
                        multiplier: multi,
                        payout: payout,
                        secret_board: bombs,
                        auto_win: true
                    });
                } else {
                    return res.status(200).json({ status: "safe", multiplier: multi });
                }
            });
        }
    });
});

// 7. MINES: CASHOUT
app.post('/api/games/mines/cashout/', authenticateJWT, (req, res) => {
    const userId = req.user.user_id;
    const { game_id } = req.body;
    
    db.get(`SELECT * FROM mines_games WHERE id = ? AND user_id = ?`, [game_id, userId], (err, game) => {
        if (err || !game) return res.status(404).json({detail: "Game not found."});
        if (game.status !== "playing") return res.status(400).json({detail: "Game is not active."});
        
        let clicked = JSON.parse(game.clicked_tiles || "[]");
        if (clicked.length === 0) return res.status(400).json({detail: "Nothing to cashout."});
        
        const payout = game.bet_amount * game.multiplier;
        db.run(`UPDATE mines_games SET status = 'cashed_out' WHERE id = ?`, [game.id], function(err) {
            if (err) return res.status(500).json({detail: "Cashout Error."});
            db.run(`UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?`, [payout, userId], function(err) {
                db.get(`SELECT wallet_balance FROM users WHERE id = ?`, [userId], (err, user) => {
                    let bombs = JSON.parse(game.secret_board || "[]");
                    return res.status(200).json({
                        status: "cashed_out",
                        payout: payout,
                        wallet_balance: user.wallet_balance,
                        secret_board: bombs
                    });
                });
            });
        });
    });
});

// --- CASINO GAME ENGINE: MEMORY MATCH ---
const MEMORY_MULTIPLIER_START = 5.00;
const MEMORY_MULTIPLIER_DROP = 0.50;
const MEMORY_EMOJIS = ['💎', '💀', '🔥', '🍒', '🍉', '🍌', '🚀', '⭐'];

// 8. MEMORY: START GAME
app.post('/api/games/memory/start/', authenticateJWT, (req, res) => {
    const userId = req.user.user_id;
    const { bet } = req.body;
    
    let betAmount = parseFloat(bet);
    if (isNaN(betAmount) || betAmount < 0) return res.status(400).json({detail: "Invalid bet."});
    if (betAmount !== 0 && (betAmount < 50 || betAmount > 100)) return res.status(400).json({detail: "Invalid bet constraints."});
    
    db.get(`SELECT wallet_balance FROM users WHERE id = ?`, [userId], (err, user) => {
        if (err || !user) return res.status(500).json({detail: "Database error."});
        if (user.wallet_balance < betAmount && betAmount > 0) return res.status(400).json({detail: "Insufficient funds."});
        
        const newBalance = user.wallet_balance - betAmount;
        db.run(`UPDATE users SET wallet_balance = ? WHERE id = ?`, [newBalance, userId], function(err) {
            if (err) return res.status(500).json({detail: "Failed to deduct bet."});
            
            // Build secret deck
            let deck = [...MEMORY_EMOJIS, ...MEMORY_EMOJIS];
            // Shuffle
            for (let i = deck.length - 1; i > 0; i--) {
                const j = Math.floor(Math.random() * (i + 1));
                [deck[i], deck[j]] = [deck[j], deck[i]];
            }
            
            const sql = `INSERT INTO memory_games (user_id, bet_amount, secret_board, matched_indices, current_flipped, status, multiplier) VALUES (?, ?, ?, ?, ?, ?, ?)`;
            db.run(sql, [userId, betAmount, JSON.stringify(deck), "[]", null, "playing", MEMORY_MULTIPLIER_START], function(err) {
                if (err) return res.status(500).json({detail: "Failed to save game session."});
                
                db.get(`SELECT id FROM memory_games WHERE user_id = ? ORDER BY id DESC LIMIT 1`, [userId], (err, row) => {
                    res.status(200).json({
                        game_id: row.id,
                        wallet_balance: newBalance,
                        status: "playing",
                        multiplier: MEMORY_MULTIPLIER_START
                    });
                });
            });
        });
    });
});

// 9. MEMORY: CLICK CARD
app.post('/api/games/memory/click/', authenticateJWT, (req, res) => {
    const userId = req.user.user_id;
    const { game_id, card_index } = req.body;
    
    db.get(`SELECT * FROM memory_games WHERE id = ? AND user_id = ?`, [game_id, userId], (err, game) => {
        if (err || !game) return res.status(404).json({detail: "Game not found."});
        if (game.status !== "playing") return res.status(400).json({detail: "Game is over."});
        
        let matched = JSON.parse(game.matched_indices || "[]");
        let secretBoard = JSON.parse(game.secret_board || "[]");
        
        if (matched.includes(card_index) || game.current_flipped === card_index) {
            return res.status(400).json({detail: "Card already revealed."});
        }
        
        const symbol = secretBoard[card_index];
        
        if (game.current_flipped === null) {
            // First card flipped
            db.run(`UPDATE memory_games SET current_flipped = ? WHERE id = ?`, [card_index, game.id], function(err) {
                if (err) return res.status(500).json({detail: "Failed to flip."});
                return res.status(200).json({ status: "flipped", symbol: symbol, match: false });
            });
        } else {
            // Second card flipped
            const firstCardIndex = game.current_flipped;
            const firstSymbol = secretBoard[firstCardIndex];
            
            if (firstSymbol === symbol) {
                // MATCH
                matched.push(firstCardIndex, card_index);
                const isWin = matched.length === 16;
                let newStatus = isWin ? 'cashed_out' : 'playing';
                
                db.run(`UPDATE memory_games SET current_flipped = NULL, matched_indices = ?, status = ? WHERE id = ?`, [JSON.stringify(matched), newStatus, game.id], function(err) {
                    if (isWin) {
                        const payout = game.bet_amount * game.multiplier;
                        db.run(`UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?`, [payout, userId], function(err) {
                            db.get(`SELECT wallet_balance FROM users WHERE id = ?`, [userId], (err, user) => {
                                return res.status(200).json({
                                    status: "cashed_out",
                                    symbol: symbol, 
                                    match: true, 
                                    multiplier: game.multiplier, 
                                    payout: payout,
                                    wallet_balance: user.wallet_balance
                                });
                            });
                        });
                    } else {
                        return res.status(200).json({
                            status: "playing",
                            symbol: symbol,
                            match: true,
                            multiplier: game.multiplier
                        });
                    }
                });
            } else {
                // MISMATCH
                let newMulti = Math.max(0, game.multiplier - MEMORY_MULTIPLIER_DROP);
                let newStatus = newMulti <= 0 ? 'exploded' : 'playing';
                
                db.run(`UPDATE memory_games SET current_flipped = NULL, multiplier = ?, status = ? WHERE id = ?`, [newMulti, newStatus, game.id], function(err) {
                    if (newStatus === 'exploded') {
                        return res.status(200).json({
                            status: "exploded",
                            symbol: symbol,
                            match: false,
                            multiplier: newMulti,
                            secret_board: secretBoard // Reveal board on loss
                        });
                    } else {
                        return res.status(200).json({
                            status: "playing",
                            symbol: symbol,
                            match: false,
                            multiplier: newMulti
                        });
                    }
                });
            }
        }
    });
});

// --- CASINO GAME ENGINE: DRAGON TOWER ---
function getTowerProb(difficulty) {
    let cols = difficulty === 'hard' ? 2 : (difficulty === 'easy' ? 4 : 3);
    return (cols - 1) / cols;
}

function getTowerMultiplier(difficulty, level) {
    if (level === 0) return 0.00;
    let prob = getTowerProb(difficulty);
    let totalProb = Math.pow(prob, level);
    let multiplier = (1 / totalProb) * 0.99; // House Edge 0.99
    return Math.floor(multiplier * 100) / 100;
}

// 10. DRAGON TOWER: START GAME
app.post('/api/games/tower/start/', authenticateJWT, (req, res) => {
    const userId = req.user.user_id;
    const { bet, difficulty } = req.body;
    
    let betAmount = parseFloat(bet);
    if (isNaN(betAmount) || betAmount < 0) return res.status(400).json({detail: "Invalid bet."});
    if (!['easy', 'medium', 'hard'].includes(difficulty)) return res.status(400).json({detail: "Invalid difficulty."});
    
    let cols = difficulty === 'hard' ? 2 : (difficulty === 'easy' ? 4 : 3);

    db.get(`SELECT wallet_balance FROM users WHERE id = ?`, [userId], (err, user) => {
        if (err || !user) return res.status(500).json({detail: "Database error."});
        if (user.wallet_balance < betAmount && betAmount > 0) return res.status(400).json({detail: "Insufficient funds."});
        
        const newBalance = user.wallet_balance - betAmount;
        db.run(`UPDATE users SET wallet_balance = ? WHERE id = ?`, [newBalance, userId], function(err) {
            if (err) return res.status(500).json({detail: "Failed to deduct."});
            
            // Build 9-row secret tower where towerData[row] = bomb_column_index
            let towerData = [];
            for (let r = 0; r < 9; r++) {
               towerData.push(Math.floor(Math.random() * cols));
            }
            
            const sql = `INSERT INTO tower_games (user_id, bet_amount, difficulty, cols, secret_tower, current_row, status, multiplier) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
            db.run(sql, [userId, betAmount, difficulty, cols, JSON.stringify(towerData), 0, "playing", 0.00], function(err) {
                db.get(`SELECT id FROM tower_games WHERE user_id = ? ORDER BY id DESC LIMIT 1`, [userId], (err, row) => {
                    res.status(200).json({
                        game_id: row.id,
                        wallet_balance: newBalance,
                        status: "playing"
                    });
                });
            });
        });
    });
});

// 11. DRAGON TOWER: CLICK TILE
app.post('/api/games/tower/click/', authenticateJWT, (req, res) => {
    const userId = req.user.user_id;
    const { game_id, r_idx, c_idx } = req.body;
    
    db.get(`SELECT * FROM tower_games WHERE id = ? AND user_id = ?`, [game_id, userId], (err, game) => {
        if (err || !game) return res.status(404).json({detail: "Game not found."});
        if (game.status !== "playing") return res.status(400).json({detail: "Game is over."});
        if (game.current_row !== r_idx) return res.status(400).json({detail: "Invalid row attempt."});
        
        let towerData = JSON.parse(game.secret_tower);
        const bombCol = towerData[r_idx];
        
        if (c_idx === bombCol) {
            // EXPLODED
            db.run(`UPDATE tower_games SET status = 'exploded' WHERE id = ?`, [game.id]);
            return res.status(200).json({ status: "exploded", secret_tower: towerData });
        } else {
            // SAFE EGG
            let nextRow = game.current_row + 1;
            let multi = getTowerMultiplier(game.difficulty, nextRow);
            
            if (nextRow === 9) {
                // Auto Cashed out Max level
                const payout = game.bet_amount * multi;
                db.run(`UPDATE tower_games SET current_row = ?, multiplier = ?, status = 'cashed_out' WHERE id = ?`, [nextRow, multi, game.id], function(err) {
                     db.run(`UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?`, [payout, userId], function(err) {
                         db.get(`SELECT wallet_balance FROM users WHERE id = ?`, [userId], (err, user) => {
                             return res.status(200).json({ status: "cashed_out", current_row: nextRow, multiplier: multi, bomb_col: bombCol, payout: payout, wallet_balance: user.wallet_balance, secret_tower: towerData });
                         });
                     });
                });
            } else {
                db.run(`UPDATE tower_games SET current_row = ?, multiplier = ? WHERE id = ?`, [nextRow, multi, game.id], function(err) {
                    return res.status(200).json({ status: "safe", current_row: nextRow, multiplier: multi, bomb_col: bombCol });
                });
            }
        }
    });
});

// 12. DRAGON TOWER: CASHOUT
app.post('/api/games/tower/cashout/', authenticateJWT, (req, res) => {
    const userId = req.user.user_id;
    const { game_id } = req.body;
    
    db.get(`SELECT * FROM tower_games WHERE id = ? AND user_id = ?`, [game_id, userId], (err, game) => {
        if (err || !game) return res.status(404).json({detail: "Game not found."});
        if (game.status !== "playing") return res.status(400).json({detail: "Game not available to cashout."});
        if (game.current_row === 0) return res.status(400).json({detail: "Must play at least 1 tile."});
        
        const payout = game.bet_amount * game.multiplier;
        db.run(`UPDATE tower_games SET status = 'cashed_out' WHERE id = ?`, [game.id], function(err) {
            db.run(`UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?`, [payout, userId], function(err) {
                db.get(`SELECT wallet_balance FROM users WHERE id = ?`, [userId], (err, user) => {
                    let towerData = JSON.parse(game.secret_tower);
                    res.status(200).json({ 
                        status: "cashed_out",
                        wallet_balance: user.wallet_balance, 
                        payout: payout,
                        secret_tower: towerData
                    });
                });
            });
        });
    });
});

// --- CASINO GAME ENGINE: COIN FLIP ---
// 13. FREESTYLE FLIP: START GAME
app.post('/api/games/flip/start/', authenticateJWT, (req, res) => {
    const userId = req.user.user_id;
    const { bet } = req.body;
    let betAmount = parseFloat(bet);
    if (isNaN(betAmount) || betAmount < 0) return res.status(400).json({detail: "Invalid bet."});

    db.get(`SELECT wallet_balance FROM users WHERE id = ?`, [userId], (err, user) => {
        if (err || !user) return res.status(500).json({detail: "Database error."});
        if (user.wallet_balance < betAmount && betAmount > 0) return res.status(400).json({detail: "Insufficient funds."});
        
        const newBalance = user.wallet_balance - betAmount;
        db.run(`UPDATE users SET wallet_balance = ? WHERE id = ?`, [newBalance, userId], function(err) {
            const sql = `INSERT INTO flip_games (user_id, bet_amount, status, multiplier) VALUES (?, ?, 'playing', 1.00)`;
            db.run(sql, [userId, betAmount], function(err) {
                res.status(200).json({ game_id: this.lastID, wallet_balance: newBalance, status: "playing" });
            });
        });
    });
});

// 14. FREESTYLE FLIP: FLIP COIN
app.post('/api/games/flip/flip/', authenticateJWT, (req, res) => {
    const userId = req.user.user_id;
    const { game_id, choice } = req.body; // 'heads' or 'tails'
    
    db.get(`SELECT * FROM flip_games WHERE id = ? AND user_id = ?`, [game_id, userId], (err, game) => {
        if (err || !game) return res.status(404).json({detail: "Game not found."});
        if (game.status !== "playing") return res.status(400).json({detail: "Game is over."});
        
        const outcome = Math.random() < 0.5 ? 'heads' : 'tails';
        const isWin = outcome === choice;
        
        if (!isWin) {
            db.run(`UPDATE flip_games SET status = 'exploded' WHERE id = ?`, [game.id]);
            return res.status(200).json({ status: "exploded", outcome: outcome });
        } else {
            let multi = game.multiplier === 1.00 ? 1.50 : game.multiplier * 1.50;
            db.run(`UPDATE flip_games SET multiplier = ? WHERE id = ?`, [multi, game.id]);
            return res.status(200).json({ status: "safe", outcome: outcome, multiplier: multi });
        }
    });
});

// 15. FREESTYLE FLIP: CASHOUT
app.post('/api/games/flip/cashout/', authenticateJWT, (req, res) => {
    const userId = req.user.user_id;
    const { game_id } = req.body;
    db.get(`SELECT * FROM flip_games WHERE id = ? AND user_id = ?`, [game_id, userId], (err, game) => {
        if (err || !game) return res.status(404).json({detail: "Game not found."});
        if (game.status !== "playing") return res.status(400).json({detail: "Game over."});
        if (game.multiplier <= 1.00) return res.status(400).json({detail: "Must play 1 round."});
        
        const payout = game.bet_amount * game.multiplier;
        db.run(`UPDATE flip_games SET status = 'cashed_out' WHERE id = ?`, [game.id], function(err) {
             db.run(`UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?`, [payout, userId], function(err) {
                 db.get(`SELECT wallet_balance FROM users WHERE id = ?`, [userId], (err, user) => {
                      res.status(200).json({ status: "cashed_out", payout: payout, wallet_balance: user.wallet_balance });
                 });
             });
        });
    });
});

// --- CASINO GAME ENGINE: CHICKEN RUN ---
const chickenConfig = {
    'easy': { lanes: 20, prob: 0.92 },
    'medium': { lanes: 15, prob: 0.86 },
    'hard': { lanes: 10, prob: 0.70 }
};

function getChickenMultiplier(prob, steps) {
    if (steps === 0) return 0.00;
    let totalProb = Math.pow(prob, steps);
    let multi = (1 / totalProb) * 0.99; // House edge 0.99
    return Math.floor(multi * 100) / 100;
}

// 16. CHICKEN RUN: START GAME
app.post('/api/games/chicken/start/', authenticateJWT, (req, res) => {
    const userId = req.user.user_id;
    const { bet, difficulty } = req.body;
    let betAmount = parseFloat(bet);
    if (isNaN(betAmount) || betAmount < 0) return res.status(400).json({detail: "Invalid bet."});
    if (!chickenConfig[difficulty]) return res.status(400).json({detail: "Invalid difficulty."});
    
    db.get(`SELECT wallet_balance FROM users WHERE id = ?`, [userId], (err, user) => {
        if (err || !user) return res.status(500).json({detail: "Database error."});
        if (user.wallet_balance < betAmount && betAmount > 0) return res.status(400).json({detail: "Insufficient funds."});
        
        const newBalance = user.wallet_balance - betAmount;
        db.run(`UPDATE users SET wallet_balance = ? WHERE id = ?`, [newBalance, userId], function(err) {
            
            let totalLanes = chickenConfig[difficulty].lanes;
            let prob = chickenConfig[difficulty].prob;
            let secretPath = [];
            for (let i = 0; i < totalLanes; i++) {
                secretPath.push(Math.random() <= prob); // true if safe
            }
            
            const sql = `INSERT INTO chicken_games (user_id, bet_amount, difficulty, total_lanes, secret_path, current_step, status, multiplier) VALUES (?, ?, ?, ?, ?, 0, 'playing', 0.00)`;
            db.run(sql, [userId, betAmount, difficulty, totalLanes, JSON.stringify(secretPath)], function(err) {
                res.status(200).json({ game_id: this.lastID, wallet_balance: newBalance, status: "playing" });
            });
        });
    });
});

// 17. CHICKEN RUN: JUMP
app.post('/api/games/chicken/jump/', authenticateJWT, (req, res) => {
    const userId = req.user.user_id;
    const { game_id } = req.body;
    
    db.get(`SELECT * FROM chicken_games WHERE id = ? AND user_id = ?`, [game_id, userId], (err, game) => {
        if (err || !game) return res.status(404).json({detail: "Game not found."});
        if (game.status !== "playing") return res.status(400).json({detail: "Game is over."});
        
        let secretPath = JSON.parse(game.secret_path);
        let nextStep = game.current_step + 1;
        
        if (nextStep > game.total_lanes) return res.status(400).json({detail: "Max step reached."});
        
        let isSafe = secretPath[game.current_step]; // index 0 is step 1
        
        if (!isSafe) {
            // EXPLODED
            db.run(`UPDATE chicken_games SET status = 'exploded' WHERE id = ?`, [game.id]);
            return res.status(200).json({ status: "exploded" });
        } else {
            // SAFE
            let prob = chickenConfig[game.difficulty].prob;
            let multi = getChickenMultiplier(prob, nextStep);
            
            if (nextStep === game.total_lanes) {
                // Auto Cashed out Max level
                const payout = game.bet_amount * multi;
                db.run(`UPDATE chicken_games SET current_step = ?, multiplier = ?, status = 'cashed_out' WHERE id = ?`, [nextStep, multi, game.id], function(err) {
                     db.run(`UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?`, [payout, userId], function(err) {
                         db.get(`SELECT wallet_balance FROM users WHERE id = ?`, [userId], (err, user) => {
                             return res.status(200).json({ status: "cashed_out", current_step: nextStep, multiplier: multi, payout: payout, wallet_balance: user.wallet_balance });
                         });
                     });
                });
            } else {
                db.run(`UPDATE chicken_games SET current_step = ?, multiplier = ? WHERE id = ?`, [nextStep, multi, game.id], function(err) {
                    return res.status(200).json({ status: "safe", current_step: nextStep, multiplier: multi });
                });
            }
        }
    });
});

// 18. CHICKEN RUN: CASHOUT
app.post('/api/games/chicken/cashout/', authenticateJWT, (req, res) => {
    const userId = req.user.user_id;
    const { game_id } = req.body;
    db.get(`SELECT * FROM chicken_games WHERE id = ? AND user_id = ?`, [game_id, userId], (err, game) => {
        if (err || !game) return res.status(404).json({detail: "Game not found."});
        if (game.status !== "playing") return res.status(400).json({detail: "Game over."});
        if (game.current_step === 0) return res.status(400).json({detail: "Must jump 1 step minimum."});
        
        const payout = game.bet_amount * game.multiplier;
        db.run(`UPDATE chicken_games SET status = 'cashed_out' WHERE id = ?`, [game.id], function(err) {
             db.run(`UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?`, [payout, userId], function(err) {
                 db.get(`SELECT wallet_balance FROM users WHERE id = ?`, [userId], (err, user) => {
                      res.status(200).json({ status: "cashed_out", payout: payout, wallet_balance: user.wallet_balance });
                 });
             });
        });
    });
});

// --- CASINO GAME ENGINE: TIC TAC TOE ---
const tttMultipliers = { easy: 1.5, medium: 2.0, hard: 5.0 };
const tttWinLines = [
    [0, 1, 2], [3, 4, 5], [6, 7, 8], // rows
    [0, 3, 6], [1, 4, 7], [2, 5, 8], // cols
    [0, 4, 8], [2, 4, 6]             // diags
  ];

function tttCheckWin(board) {
    for (let line of tttWinLines) {
        let [a,b,c] = line;
        if(board[a] && board[a] === board[b] && board[a] === board[c]) return board[a];
    }
    if(!board.includes(null)) return 'draw';
    return null;
}

function tttMinimax(board, depth, isMax) {
    let result = tttCheckWin(board);
    if(result === 'O') return 10 - depth;
    if(result === 'X') return depth - 10;
    if(result === 'draw') return 0;

    let bestScore = isMax ? -Infinity : Infinity;
    for(let i=0; i<9; i++) {
        if(board[i] === null) {
            board[i] = isMax ? 'O' : 'X';
            let score = tttMinimax(board, depth+1, !isMax);
            board[i] = null;
            bestScore = isMax ? Math.max(score, bestScore) : Math.min(score, bestScore);
        }
    }
    return bestScore;
}

function tttGetWinningOrBlockingMove(board, symbol) {
     for (let line of tttWinLines) {
       let [a, b, c] = line;
       let vals = [board[a], board[b], board[c]];
       if (vals.filter(v => v === symbol).length === 2 && vals.includes(null)) {
         return line[vals.indexOf(null)];
       }
     }
     return null;
}

function getCpuMove(board, difficulty) {
    let emptySpaces = board.map((v,i) => v===null?i:null).filter(v=>v!==null);
    if(emptySpaces.length === 0) return -1;
    
    if(difficulty === 'easy') {
        if(Math.random() < 0.2) {
            let move = tttGetWinningOrBlockingMove(board, 'O') || tttGetWinningOrBlockingMove(board, 'X');
            if(move !== null && move !== undefined) return move;
        }
        return emptySpaces[Math.floor(Math.random()*emptySpaces.length)];
    } else if (difficulty === 'medium') {
        let move = tttGetWinningOrBlockingMove(board, 'O') || tttGetWinningOrBlockingMove(board, 'X');
        if(move !== null && move !== undefined) return move;
        if(board[4] === null) return 4;
        return emptySpaces[Math.floor(Math.random()*emptySpaces.length)];
    } else {
        // Hard
        let bestScore = -Infinity;
        let move = -1;
        for(let i=0; i<9; i++) {
            if(board[i] === null) {
                board[i] = 'O';
                let score = tttMinimax(board, 0, false);
                board[i] = null;
                if(score > bestScore) {
                    bestScore = score;
                    move = i;
                }
            }
        }
        return move;
    }
}

app.post('/api/games/tictactoe/start/', authenticateJWT, (req, res) => {
    const userId = req.user.user_id;
    const { bet, difficulty } = req.body;
    let betAmount = parseFloat(bet);
    if (isNaN(betAmount) || betAmount < 0) return res.status(400).json({detail: "Invalid bet."});
    
    // Limits validation: free or 50 to 100
    if (betAmount !== 0 && (betAmount < 50 || betAmount > 100)) {
       return res.status(400).json({detail: "Bet must be exactly ₹0.00, or between ₹50.00 and ₹100.00!"});
    }
    
    db.get(`SELECT wallet_balance FROM users WHERE id = ?`, [userId], (err, user) => {
        if (err || !user) return res.status(500).json({detail: "Database error."});
        if (user.wallet_balance < betAmount && betAmount > 0) return res.status(400).json({detail: "Insufficient funds."});
        
        const newBalance = user.wallet_balance - betAmount;
        db.run(`UPDATE users SET wallet_balance = ? WHERE id = ?`, [newBalance, userId], function(err) {
            const initialBoard = Array(9).fill(null);
            const sql = `INSERT INTO tictactoe_games (user_id, bet_amount, difficulty, board, status) VALUES (?, ?, ?, ?, 'playing')`;
            db.run(sql, [userId, betAmount, difficulty, JSON.stringify(initialBoard)], function(err) {
                res.status(200).json({ game_id: this.lastID, wallet_balance: newBalance, status: "playing" });
            });
        });
    });
});

app.post('/api/games/tictactoe/move/', authenticateJWT, (req, res) => {
    const userId = req.user.user_id;
    const { game_id, spot_idx } = req.body;
    
    if (spot_idx < 0 || spot_idx > 8) return res.status(400).json({detail: "Invalid move."});
    
    db.get(`SELECT * FROM tictactoe_games WHERE id = ? AND user_id = ?`, [game_id, userId], (err, game) => {
        if (err || !game) return res.status(404).json({detail: "Game not found."});
        if (game.status !== "playing") return res.status(400).json({detail: "Game over."});
        
        let board = JSON.parse(game.board);
        if (board[spot_idx] !== null) return res.status(400).json({detail: "Spot taken."});
        
        // Apply player move
        board[spot_idx] = 'X';
        
        // Check Player Win/Draw
        let state = tttCheckWin(board);
        if (state === 'X') {
            // Player Won
            let payout = game.bet_amount * tttMultipliers[game.difficulty];
            db.run(`UPDATE tictactoe_games SET board = ?, status = 'win' WHERE id = ?`, [JSON.stringify(board), game.id]);
            db.run(`UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?`, [payout, userId]);
            return res.status(200).json({ status: "win", board: board, payout: payout });
        } else if (state === 'draw') {
             // Draw (Return bet)
            let payout = game.bet_amount;
            db.run(`UPDATE tictactoe_games SET board = ?, status = 'draw' WHERE id = ?`, [JSON.stringify(board), game.id]);
            db.run(`UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?`, [payout, userId]);
            return res.status(200).json({ status: "draw", board: board, payout: payout });
        }
        
        // CPU Turn
        let cpuMoveIdx = getCpuMove(board, game.difficulty);
        if (cpuMoveIdx !== -1) {
            board[cpuMoveIdx] = 'O';
        }
        
        // Check CPU Win/Draw
        state = tttCheckWin(board);
        if (state === 'O') {
            db.run(`UPDATE tictactoe_games SET board = ?, status = 'loss' WHERE id = ?`, [JSON.stringify(board), game.id]);
            return res.status(200).json({ status: "loss", board: board, cpu_move: cpuMoveIdx });
        } else if (state === 'draw') {
            let payout = game.bet_amount;
            db.run(`UPDATE tictactoe_games SET board = ?, status = 'draw' WHERE id = ?`, [JSON.stringify(board), game.id]);
            db.run(`UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?`, [payout, userId]);
            return res.status(200).json({ status: "draw", board: board, payout: payout, cpu_move: cpuMoveIdx });
        }
        
        // Game continues
        db.run(`UPDATE tictactoe_games SET board = ? WHERE id = ?`, [JSON.stringify(board), game.id]);
        return res.status(200).json({ status: "playing", board: board, cpu_move: cpuMoveIdx });
    });
});

// --- CASINO GAME ENGINE: MEMORY MATCH ---
const memorySymbols = ['🍎','🍎','🍌','🍌','🍇','🍇','🍒','🍒','🍉','🍉','🍓','🍓','🥝','🥝','🍍','🍍'];

function shuffleArray(array) {
    let arr = [...array];
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

app.post('/api/games/memory/start/', authenticateJWT, (req, res) => {
    const userId = req.user.user_id;
    const { bet } = req.body;
    let betAmount = parseFloat(bet);
    if (isNaN(betAmount) || betAmount < 0) return res.status(400).json({detail: "Invalid bet."});
    
    db.get(`SELECT wallet_balance FROM users WHERE id = ?`, [userId], (err, user) => {
        if (err || !user) return res.status(500).json({detail: "Database error."});
        if (user.wallet_balance < betAmount && betAmount > 0) return res.status(400).json({detail: "Insufficient funds."});
        
        const newBalance = user.wallet_balance - betAmount;
        db.run(`UPDATE users SET wallet_balance = ? WHERE id = ?`, [newBalance, userId], function(err) {
            
            let shuffledBoard = shuffleArray(memorySymbols);
            const sql = `INSERT INTO memory_games (user_id, bet_amount, secret_board, matched_pairs, flipped_indexes, status) VALUES (?, ?, ?, '[]', '[]', 'playing')`;
            
            db.run(sql, [userId, betAmount, JSON.stringify(shuffledBoard)], function(err) {
                res.status(200).json({ game_id: this.lastID, wallet_balance: newBalance, status: "playing" });
            });
        });
    });
});

app.post('/api/games/memory/click/', authenticateJWT, (req, res) => {
    const userId = req.user.user_id;
    const { game_id, card_index } = req.body;
    
    db.get(`SELECT * FROM memory_games WHERE id = ? AND user_id = ?`, [game_id, userId], (err, game) => {
        if (err || !game) return res.status(404).json({detail: "Game not found."});
        if (game.status !== "playing") return res.status(400).json({detail: "Game over."});
        
        let board = JSON.parse(game.secret_board);
        let matched = JSON.parse(game.matched_pairs);
        let flipped = JSON.parse(game.flipped_indexes);
        
        if (card_index < 0 || card_index > 15) return res.status(400).json({detail: "Invalid card."});
        if (matched.includes(card_index) || flipped.includes(card_index)) return res.status(400).json({detail: "Card already flipped."});
        
        let symbol = board[card_index];
        flipped.push(card_index);
        
        if (flipped.length === 1) {
            // Wait for 2nd card
            db.run(`UPDATE memory_games SET flipped_indexes = ? WHERE id = ?`, [JSON.stringify(flipped), game.id]);
            return res.status(200).json({ status: "flipped", symbol: symbol });
        } else if (flipped.length === 2) {
            let firstIdx = flipped[0];
            let secondIdx = flipped[1];
            
            if (board[firstIdx] === board[secondIdx]) {
                // MATCH
                matched.push(firstIdx, secondIdx);
                flipped = []; // Reset active flips
                
                if (matched.length === 16) {
                    // WON THE GAME!
                    const payout = game.bet_amount * 5.00;
                    db.run(`UPDATE memory_games SET status = 'win', matched_pairs = ?, flipped_indexes = '[]' WHERE id = ?`, [JSON.stringify(matched), game.id]);
                    db.run(`UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?`, [payout, userId]);
                    db.get(`SELECT wallet_balance FROM users WHERE id = ?`, [userId], (err, user) => {
                        return res.status(200).json({ status: "match_win", symbol: symbol, payout: payout, wallet_balance: user.wallet_balance });
                    });
                } else {
                    db.run(`UPDATE memory_games SET matched_pairs = ?, flipped_indexes = '[]' WHERE id = ?`, [JSON.stringify(matched), game.id]);
                    return res.status(200).json({ status: "match", symbol: symbol });
                }
            } else {
                // MISMATCH
                flipped = []; // Reset active flips
                db.run(`UPDATE memory_games SET flipped_indexes = '[]' WHERE id = ?`, [game.id]);
                return res.status(200).json({ status: "mismatch", symbol: symbol, pair: [firstIdx, secondIdx] });
            }
        }
    });
});

// --- SERVER START ---
const PORT = 8000; // We keep it at 8000 so the frontend fetch URLs don't break!
app.listen(PORT, () => {
    console.log(`🚀 Node.js Backend is LIVE on http://localhost:${PORT}/`);
    console.log(`Database tables completely synthesized.`);
});
