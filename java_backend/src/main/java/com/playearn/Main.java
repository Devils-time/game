package com.playearn;

import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.HttpStatus;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.SQLException;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Date;
import io.github.cdimascio.dotenv.Dotenv;
import org.mindrot.jbcrypt.BCrypt;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import java.sql.PreparedStatement;

public class Main {
    
    private static Dotenv dotenv = Dotenv.load();
    private static final String SECRET_KEY = dotenv.get("SECRET_KEY", "casino-hyper-secret-token");
    private static Connection dbConnection;

    public static void main(String[] args) {
        
        System.out.println("Starting Java Backend...");
        initDatabase();

        Javalin app = Javalin.create(config -> {
            config.plugins.enableCors(cors -> {
                cors.add(it -> {
                    it.anyHost(); // Matches `app.use(cors())`
                });
            });
        }).start(8000); // Matches `app.listen(PORT)`
        
        System.out.println("🚀 Java Backend is LIVE on http://localhost:8000/");

        // Rate Limiter / JWT filter equivalent logic
        app.before("/api/*", ctx -> {
            String path = ctx.path();
            if (path.startsWith("/api/auth/")) {
                return; // Auth routes don't need JWT
            }

            String authHeader = ctx.header("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                try {
                    Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
                    JWTVerifier verifier = JWT.require(algorithm).build();
                    DecodedJWT jwt = verifier.verify(token);
                    
                    int userId = jwt.getClaim("user_id").asInt();
                    ctx.attribute("user_id", userId);
                } catch (Exception e) {
                    ctx.status(HttpStatus.UNAUTHORIZED).json(Map.of("detail", "Expired or invalid session."));
                }
            } else {
                ctx.status(HttpStatus.UNAUTHORIZED).json(Map.of("detail", "Not Authorized"));
            }
        });

        // 1. REGISTER
        app.post("/api/auth/register/", ctx -> {
            Map body = ctx.bodyAsClass(Map.class);
            String username = (String) body.get("username");
            String email = (String) body.get("email");
            String phoneParameter = (String) body.get("phone_number");
            String password = (String) body.get("password");

            if (username == null || password == null) {
                ctx.status(HttpStatus.BAD_REQUEST).json(Map.of("detail", "Username and password required!"));
                return;
            }

            String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(10));

            try (PreparedStatement pstmt = dbConnection.prepareStatement(
                    "INSERT INTO users (username, email, phone_number, password_hash, wallet_balance) VALUES (?, ?, ?, ?, ?)")) {
                pstmt.setString(1, username);
                pstmt.setString(2, email);
                pstmt.setString(3, phoneParameter);
                pstmt.setString(4, hashedPassword);
                pstmt.setDouble(5, 0.00);
                pstmt.executeUpdate();

                ResultSet rs = dbConnection.createStatement().executeQuery("SELECT last_insert_rowid()");
                int lastId = rs.getInt(1);

                ctx.status(HttpStatus.CREATED).json(Map.of("message", "Registration successful!", "user_id", lastId));
            } catch (SQLException e) {
                if (e.getMessage().contains("UNIQUE constraint failed")) {
                    ctx.status(HttpStatus.BAD_REQUEST).json(Map.of("detail", "Username already exists!"));
                } else {
                    ctx.status(HttpStatus.INTERNAL_SERVER_ERROR).json(Map.of("detail", "Server error creating user."));
                }
            }
        });

        // 2. LOGIN
        app.post("/api/auth/login/", ctx -> {
            Map body = ctx.bodyAsClass(Map.class);
            String username = (String) body.get("username");
            String password = (String) body.get("password");

            try (PreparedStatement pstmt = dbConnection.prepareStatement("SELECT * FROM users WHERE username = ?")) {
                pstmt.setString(1, username);
                ResultSet rs = pstmt.executeQuery();

                if (!rs.next()) {
                    ctx.status(HttpStatus.UNAUTHORIZED).json(Map.of("detail", "User does not exist."));
                    return;
                }

                String hash = rs.getString("password_hash");
                if (!BCrypt.checkpw(password, hash)) {
                    ctx.status(HttpStatus.UNAUTHORIZED).json(Map.of("detail", "Incorrect password."));
                    return;
                }

                int userId = rs.getInt("id");
                
                Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
                String token = JWT.create()
                    .withClaim("user_id", userId)
                    .withClaim("username", username)
                    .withExpiresAt(new Date(System.currentTimeMillis() + (24 * 60 * 60 * 1000))) // 24h
                    .sign(algorithm);

                ctx.json(Map.of("access", token));
            } catch (SQLException e) {
                ctx.status(HttpStatus.INTERNAL_SERVER_ERROR).json(Map.of("detail", "Database error."));
            }
        });

        // 4. FETCH WALLET BALANCE
        app.get("/api/wallet/", ctx -> {
            Integer userId = ctx.attribute("user_id");
            if (userId == null) return; // intercepted by before filter if unauthorized

            try (PreparedStatement pstmt = dbConnection.prepareStatement("SELECT wallet_balance FROM users WHERE id = ?")) {
                pstmt.setInt(1, userId);
                ResultSet rs = pstmt.executeQuery();
                if (rs.next()) {
                    ctx.json(Map.of("wallet_balance", rs.getDouble("wallet_balance")));
                }
            } catch (SQLException e) {
                ctx.status(HttpStatus.INTERNAL_SERVER_ERROR).json(Map.of("detail", "Error fetching wallet."));
            }
        });

        // 4.5 DEPOSIT GATEWAY
        app.post("/api/wallet/deposit/", ctx -> {
            ctx.status(HttpStatus.NOT_IMPLEMENTED).json(Map.of("detail", "Production Payment Gateway not yet connected."));
        });
        
    }

    private static void initDatabase() {
        try {
            // Immediately connects to (or builds) custom database file exactly like `new sqlite3.Database('./database.sqlite')`
            dbConnection = DriverManager.getConnection("jdbc:sqlite:database.sqlite");
            System.out.println("✅ Successfully connected to SQLite Database.");

            Statement stmt = dbConnection.createStatement();

            // Users Table
            stmt.execute("CREATE TABLE IF NOT EXISTS users (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "username TEXT UNIQUE," +
                "email TEXT," +
                "phone_number TEXT," +
                "password_hash TEXT," +
                "wallet_balance REAL DEFAULT 0.00" +
            ")");
            
            // Mines Table
            stmt.execute("CREATE TABLE IF NOT EXISTS mines_games (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "user_id INTEGER," +
                "bet_amount REAL," +
                "mines_count INTEGER," +
                "secret_board TEXT," +
                "clicked_tiles TEXT," +
                "status TEXT," +
                "multiplier REAL DEFAULT 1.0," +
                "FOREIGN KEY(user_id) REFERENCES users(id)" +
            ")");

            // Flip Table
            stmt.execute("CREATE TABLE IF NOT EXISTS flip_games (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "user_id INTEGER," +
                "bet_amount REAL," +
                "status TEXT," +
                "multiplier REAL DEFAULT 1.00," +
                "FOREIGN KEY(user_id) REFERENCES users(id)" +
            ")");

            // Chicken
            stmt.execute("CREATE TABLE IF NOT EXISTS chicken_games (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "user_id INTEGER," +
                "bet_amount REAL," +
                "difficulty TEXT," +
                "total_lanes INTEGER," +
                "secret_path TEXT," +
                "current_step INTEGER DEFAULT 0," +
                "status TEXT," +
                "multiplier REAL DEFAULT 0.00," +
                "FOREIGN KEY(user_id) REFERENCES users(id)" +
            ")");

            // Tic Tac Toe
            stmt.execute("CREATE TABLE IF NOT EXISTS tictactoe_games (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "user_id INTEGER," +
                "bet_amount REAL," +
                "difficulty TEXT," +
                "board TEXT," +
                "status TEXT," +
                "FOREIGN KEY(user_id) REFERENCES users(id)" +
            ")");

            // Dragon Tower
            stmt.execute("CREATE TABLE IF NOT EXISTS tower_games (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "user_id INTEGER," +
                "bet_amount REAL," +
                "difficulty TEXT," +
                "cols INTEGER," +
                "secret_tower TEXT," +
                "current_row INTEGER DEFAULT 0," +
                "status TEXT," +
                "multiplier REAL DEFAULT 0.00," +
                "FOREIGN KEY(user_id) REFERENCES users(id)" +
            ")");

            // Memory Match
            stmt.execute("CREATE TABLE IF NOT EXISTS memory_games (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "user_id INTEGER," +
                "bet_amount REAL," +
                "secret_board TEXT," +
                "matched_pairs TEXT," +
                "flipped_indexes TEXT," +
                "status TEXT," +
                "FOREIGN KEY(user_id) REFERENCES users(id)" +
            ")");

            stmt.close();
            System.out.println("✅ Database tables completely synthesized.");
        } catch (SQLException e) {
            System.err.println("Database Error: " + e.getMessage());
        }
    }
}
