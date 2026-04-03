from flask import Flask, request, jsonify, g
from flask_cors import CORS
import sqlite3
import bcrypt
import jwt
import json
import random
import datetime
import math
import os
from functools import wraps

app = Flask(__name__)
# Enable CORS for all routes (to replicate app.use(cors()))
CORS(app)

SECRET_KEY = os.environ.get("SECRET_KEY", "casino-hyper-secret-token")
DATABASE = './database.sqlite'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT,
            phone_number TEXT,
            password_hash TEXT,
            wallet_balance REAL DEFAULT 0.00
        )''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS mines_games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            bet_amount REAL,
            mines_count INTEGER,
            secret_board TEXT,
            clicked_tiles TEXT,
            status TEXT,
            multiplier REAL DEFAULT 1.0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS flip_games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            bet_amount REAL,
            status TEXT,
            multiplier REAL DEFAULT 1.00,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS chicken_games (
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
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS tictactoe_games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            bet_amount REAL,
            difficulty TEXT,
            board TEXT,
            status TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS tower_games (
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
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS memory_games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            bet_amount REAL,
            secret_board TEXT,
            matched_pairs TEXT,
            flipped_indexes TEXT,
            status TEXT,
            multiplier REAL DEFAULT 5.0,
            current_flipped INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        db.commit()

# --- MIDDLEWARE ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'detail': 'Not Authorized'}), 401
        token = auth_header.split(' ')[1]
        try:
            # Replicating jsonwebtoken logic mapping the payload structure
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user = decoded
        except Exception as e:
            return jsonify({'detail': 'Expired or invalid session.'}), 401
        return f(*args, **kwargs)
    return decorated

# Setup DB immediately on script start
init_db()

# --- AUTHENTICATION ---
@app.route('/api/auth/register/', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    phone_number = data.get('phone_number')
    password = data.get('password')

    if not username or not password:
        return jsonify({'detail': 'Username and password required!'}), 400

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute('INSERT INTO users (username, email, phone_number, password_hash, wallet_balance) VALUES (?, ?, ?, ?, ?)',
                       (username, email, phone_number, hashed_pw, 0.00))
        db.commit()
        return jsonify({'message': 'Registration successful!', 'user_id': cursor.lastrowid}), 201
    except sqlite3.IntegrityError:
        return jsonify({'detail': 'Username already exists!'}), 400
    except Exception as e:
        return jsonify({'detail': 'Server error creating user.'}), 500

@app.route('/api/auth/login/', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()

    if not user:
        return jsonify({'detail': 'User does not exist.'}), 401
    
    if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        return jsonify({'detail': 'Incorrect password.'}), 401
    
    # Needs exp format equivalent to '24h' from NodeJS
    exp_time = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    payload = {'user_id': user['id'], 'username': user['username'], 'exp': exp_time}
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    
    return jsonify({'access': token})

# --- WALLET ---
@app.route('/api/wallet/', methods=['GET'])
@token_required
def get_wallet():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT wallet_balance FROM users WHERE id = ?', (request.user['user_id'],))
    row = cursor.fetchone()
    if not row:
        return jsonify({'detail': 'Error fetching wallet.'}), 500
    return jsonify({'wallet_balance': row['wallet_balance']})

@app.route('/api/wallet/deposit/', methods=['POST'])
@token_required
def deposit_wallet():
    return jsonify({'detail': 'Production Payment Gateway not yet connected.'}), 501

# --- GAME: MINES ---
HOUSE_EDGE = 0.99
def get_mines_multiplier(mines, gems_revealed):
    if gems_revealed == 0: return 1.0
    prob = 1.0
    remaining_safe = 25 - mines
    remaining_total = 25
    for i in range(gems_revealed):
        prob *= (remaining_safe / remaining_total)
        remaining_safe -= 1
        remaining_total -= 1
    multiplier = (1 / prob) * HOUSE_EDGE
    return math.floor(multiplier * 100) / 100

@app.route('/api/games/mines/start/', methods=['POST'])
@token_required
def mines_start():
    user_id = request.user['user_id']
    data = request.json
    bet_amount = float(data.get('bet', 0))
    mines = int(data.get('mines', 0))

    if bet_amount < 0: return jsonify({'detail': 'Invalid bet.'}), 400
    if mines < 1 or mines > 24: return jsonify({'detail': 'Invalid mines count.'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT wallet_balance FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()

    if not user: return jsonify({'detail': 'Database error.'}), 500
    if user['wallet_balance'] < bet_amount and bet_amount > 0: return jsonify({'detail': 'Insufficient funds.'}), 400

    new_balance = user['wallet_balance'] - bet_amount
    cursor.execute('UPDATE users SET wallet_balance = ? WHERE id = ?', (new_balance, user_id))

    deck = list(range(25))
    bomb_positions = random.sample(deck, mines)

    cursor.execute('INSERT INTO mines_games (user_id, bet_amount, mines_count, secret_board, clicked_tiles, status) VALUES (?, ?, ?, ?, ?, ?)',
                   (user_id, bet_amount, mines, json.dumps(bomb_positions), "[]", "playing"))
    game_id = cursor.lastrowid
    db.commit()

    return jsonify({'game_id': game_id, 'wallet_balance': new_balance, 'status': 'playing'})

@app.route('/api/games/mines/click/', methods=['POST'])
@token_required
def mines_click():
    user_id = request.user['user_id']
    data = request.json
    game_id = data.get('game_id')
    tile = int(data.get('tile'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM mines_games WHERE id = ? AND user_id = ?', (game_id, user_id))
    game = cursor.fetchone()

    if not game: return jsonify({'detail': 'Game not found.'}), 404
    if game['status'] != 'playing': return jsonify({'detail': 'Game is over.'}), 400

    clicked = json.loads(game['clicked_tiles'] or "[]")
    if tile in clicked: return jsonify({'detail': 'Tile already clicked.'}), 400

    bombs = json.loads(game['secret_board'] or "[]")

    if tile in bombs:
        cursor.execute('UPDATE mines_games SET status = "exploded" WHERE id = ?', (game['id'],))
        db.commit()
        return jsonify({'status': 'exploded', 'secret_board': bombs})
    else:
        clicked.append(tile)
        multi = get_mines_multiplier(game['mines_count'], len(clicked))
        is_auto_win = len(clicked) == (25 - game['mines_count'])

        new_status = 'cashed_out' if is_auto_win else 'playing'
        cursor.execute('UPDATE mines_games SET clicked_tiles = ?, multiplier = ?, status = ? WHERE id = ?',
                       (json.dumps(clicked), multi, new_status, game['id']))
        
        if is_auto_win:
            payout = game['bet_amount'] * multi
            cursor.execute('UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?', (payout, user_id))
            db.commit()
            return jsonify({'status': 'cashed_out', 'multiplier': multi, 'payout': payout, 'secret_board': bombs, 'auto_win': True})
        else:
            db.commit()
            return jsonify({'status': 'safe', 'multiplier': multi})

@app.route('/api/games/mines/cashout/', methods=['POST'])
@token_required
def mines_cashout():
    user_id = request.user['user_id']
    data = request.json
    game_id = data.get('game_id')

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM mines_games WHERE id = ? AND user_id = ?', (game_id, user_id))
    game = cursor.fetchone()

    if not game: return jsonify({'detail': 'Game not found.'}), 404
    if game['status'] != 'playing': return jsonify({'detail': 'Game is not active.'}), 400

    clicked = json.loads(game['clicked_tiles'] or "[]")
    if len(clicked) == 0: return jsonify({'detail': 'Nothing to cashout.'}), 400

    payout = game['bet_amount'] * game['multiplier']
    cursor.execute('UPDATE mines_games SET status = "cashed_out" WHERE id = ?', (game['id'],))
    cursor.execute('UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?', (payout, user_id))
    db.commit()
    
    cursor.execute('SELECT wallet_balance FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    bombs = json.loads(game['secret_board'] or "[]")
    
    return jsonify({'status': 'cashed_out', 'payout': payout, 'wallet_balance': user['wallet_balance'], 'secret_board': bombs})

# --- GAME: MEMORY MATCH ---
MEMORY_SYMBOLS = ['🍎','🍎','🍌','🍌','🍇','🍇','🍒','🍒','🍉','🍉','🍓','🍓','🥝','🥝','🍍','🍍']

@app.route('/api/games/memory/start/', methods=['POST'])
@token_required
def memory_start():
    user_id = request.user['user_id']
    bet_amount = float(request.json.get('bet', 0))

    if bet_amount < 0: return jsonify({'detail': 'Invalid bet.'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT wallet_balance FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()

    if not user: return jsonify({'detail': 'Database error.'}), 500
    if user['wallet_balance'] < bet_amount and bet_amount > 0: return jsonify({'detail': 'Insufficient funds.'}), 400

    new_balance = user['wallet_balance'] - bet_amount
    cursor.execute('UPDATE users SET wallet_balance = ? WHERE id = ?', (new_balance, user_id))

    deck = list(MEMORY_SYMBOLS)
    random.shuffle(deck)

    cursor.execute('INSERT INTO memory_games (user_id, bet_amount, secret_board, matched_pairs, flipped_indexes, status) VALUES (?, ?, ?, ?, ?, ?)',
                   (user_id, bet_amount, json.dumps(deck), "[]", "[]", "playing"))
    game_id = cursor.lastrowid
    db.commit()

    return jsonify({'game_id': game_id, 'wallet_balance': new_balance, 'status': 'playing'})

@app.route('/api/games/memory/click/', methods=['POST'])
@token_required
def memory_click():
    user_id = request.user['user_id']
    data = request.json
    game_id = data.get('game_id')
    card_index = int(data.get('card_index'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM memory_games WHERE id = ? AND user_id = ?', (game_id, user_id))
    game = cursor.fetchone()

    if not game: return jsonify({'detail': 'Game not found.'}), 404
    if game['status'] != 'playing': return jsonify({'detail': 'Game over.'}), 400

    board = json.loads(game['secret_board'])
    matched = json.loads(game['matched_pairs'] or "[]")
    flipped = json.loads(game['flipped_indexes'] or "[]")

    if card_index < 0 or card_index > 15: return jsonify({'detail': 'Invalid card.'}), 400
    if card_index in matched or card_index in flipped: return jsonify({'detail': 'Card already flipped.'}), 400

    symbol = board[card_index]
    flipped.append(card_index)

    if len(flipped) == 1:
        cursor.execute('UPDATE memory_games SET flipped_indexes = ? WHERE id = ?', (json.dumps(flipped), game['id']))
        db.commit()
        return jsonify({'status': 'flipped', 'symbol': symbol})
    elif len(flipped) == 2:
        first_idx = flipped[0]
        second_idx = flipped[1]

        if board[first_idx] == board[second_idx]:
            matched.extend([first_idx, second_idx])
            flipped = []
            
            if len(matched) == 16:
                payout = game['bet_amount'] * 5.00
                cursor.execute('UPDATE memory_games SET status = "win", matched_pairs = ?, flipped_indexes = "[]" WHERE id = ?', (json.dumps(matched), game['id']))
                cursor.execute('UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?', (payout, user_id))
                db.commit()
                cursor.execute('SELECT wallet_balance FROM users WHERE id = ?', (user_id,))
                user = cursor.fetchone()
                return jsonify({'status': 'match_win', 'symbol': symbol, 'payout': payout, 'wallet_balance': user['wallet_balance']})
            else:
                cursor.execute('UPDATE memory_games SET matched_pairs = ?, flipped_indexes = "[]" WHERE id = ?', (json.dumps(matched), game['id']))
                db.commit()
                return jsonify({'status': 'match', 'symbol': symbol})
        else:
            flipped = []
            cursor.execute('UPDATE memory_games SET flipped_indexes = "[]" WHERE id = ?', (game['id'],))
            db.commit()
            return jsonify({'status': 'mismatch', 'symbol': symbol, 'pair': [first_idx, second_idx]})

# --- GAME: DRAGON TOWER ---
def get_tower_prob(difficulty):
    cols = 2 if difficulty == 'hard' else (4 if difficulty == 'easy' else 3)
    return (cols - 1) / cols

def get_tower_multiplier(difficulty, level):
    if level == 0: return 0.00
    prob = get_tower_prob(difficulty)
    total_prob = prob ** level
    multiplier = (1 / total_prob) * 0.99
    return math.floor(multiplier * 100) / 100

@app.route('/api/games/tower/start/', methods=['POST'])
@token_required
def tower_start():
    user_id = request.user['user_id']
    data = request.json
    bet_amount = float(data.get('bet', 0))
    difficulty = data.get('difficulty')

    if bet_amount < 0: return jsonify({'detail': 'Invalid bet.'}), 400
    if difficulty not in ['easy', 'medium', 'hard']: return jsonify({'detail': 'Invalid difficulty.'}), 400

    cols = 2 if difficulty == 'hard' else (4 if difficulty == 'easy' else 3)

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT wallet_balance FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()

    if not user: return jsonify({'detail': 'Database error.'}), 500
    if user['wallet_balance'] < bet_amount and bet_amount > 0: return jsonify({'detail': 'Insufficient funds.'}), 400

    new_balance = user['wallet_balance'] - bet_amount
    cursor.execute('UPDATE users SET wallet_balance = ? WHERE id = ?', (new_balance, user_id))

    tower_data = [random.randint(0, cols - 1) for _ in range(9)]

    cursor.execute('INSERT INTO tower_games (user_id, bet_amount, difficulty, cols, secret_tower, current_row, status, multiplier) VALUES (?, ?, ?, ?, ?, 0, "playing", 0.00)',
                   (user_id, bet_amount, difficulty, cols, json.dumps(tower_data)))
    game_id = cursor.lastrowid
    db.commit()

    return jsonify({'game_id': game_id, 'wallet_balance': new_balance, 'status': 'playing'})

@app.route('/api/games/tower/click/', methods=['POST'])
@token_required
def tower_click():
    user_id = request.user['user_id']
    data = request.json
    game_id = data.get('game_id')
    r_idx = int(data.get('r_idx'))
    c_idx = int(data.get('c_idx'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM tower_games WHERE id = ? AND user_id = ?', (game_id, user_id))
    game = cursor.fetchone()

    if not game: return jsonify({'detail': 'Game not found.'}), 404
    if game['status'] != 'playing': return jsonify({'detail': 'Game is over.'}), 400
    if game['current_row'] != r_idx: return jsonify({'detail': 'Invalid row attempt.'}), 400

    tower_data = json.loads(game['secret_tower'])
    bomb_col = tower_data[r_idx]

    if c_idx == bomb_col:
        cursor.execute('UPDATE tower_games SET status = "exploded" WHERE id = ?', (game['id'],))
        db.commit()
        return jsonify({'status': 'exploded', 'secret_tower': tower_data})
    else:
        next_row = game['current_row'] + 1
        multi = get_tower_multiplier(game['difficulty'], next_row)

        if next_row == 9:
            payout = game['bet_amount'] * multi
            cursor.execute('UPDATE tower_games SET current_row = ?, multiplier = ?, status = "cashed_out" WHERE id = ?', (next_row, multi, game['id']))
            cursor.execute('UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?', (payout, user_id))
            db.commit()
            cursor.execute('SELECT wallet_balance FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            return jsonify({'status': 'cashed_out', 'current_row': next_row, 'multiplier': multi, 'bomb_col': bomb_col, 'payout': payout, 'wallet_balance': user['wallet_balance'], 'secret_tower': tower_data})
        else:
            cursor.execute('UPDATE tower_games SET current_row = ?, multiplier = ? WHERE id = ?', (next_row, multi, game['id']))
            db.commit()
            return jsonify({'status': 'safe', 'current_row': next_row, 'multiplier': multi, 'bomb_col': bomb_col})

@app.route('/api/games/tower/cashout/', methods=['POST'])
@token_required
def tower_cashout():
    user_id = request.user['user_id']
    data = request.json
    game_id = data.get('game_id')

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM tower_games WHERE id = ? AND user_id = ?', (game_id, user_id))
    game = cursor.fetchone()

    if not game: return jsonify({'detail': 'Game not found.'}), 404
    if game['status'] != 'playing': return jsonify({'detail': 'Game not available to cashout.'}), 400
    if game['current_row'] == 0: return jsonify({'detail': 'Must play at least 1 tile.'}), 400

    payout = game['bet_amount'] * game['multiplier']
    cursor.execute('UPDATE tower_games SET status = "cashed_out" WHERE id = ?', (game['id'],))
    cursor.execute('UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?', (payout, user_id))
    db.commit()

    cursor.execute('SELECT wallet_balance FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    tower_data = json.loads(game['secret_tower'])
    
    return jsonify({'status': 'cashed_out', 'wallet_balance': user['wallet_balance'], 'payout': payout, 'secret_tower': tower_data})

# --- GAME: FLIP ---
@app.route('/api/games/flip/start/', methods=['POST'])
@token_required
def flip_start():
    user_id = request.user['user_id']
    bet_amount = float(request.json.get('bet', 0))

    if bet_amount < 0: return jsonify({'detail': 'Invalid bet.'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT wallet_balance FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()

    if not user: return jsonify({'detail': 'Database error.'}), 500
    if user['wallet_balance'] < bet_amount and bet_amount > 0: return jsonify({'detail': 'Insufficient funds.'}), 400

    new_balance = user['wallet_balance'] - bet_amount
    cursor.execute('UPDATE users SET wallet_balance = ? WHERE id = ?', (new_balance, user_id))

    cursor.execute('INSERT INTO flip_games (user_id, bet_amount, status, multiplier) VALUES (?, ?, "playing", 1.00)', (user_id, bet_amount))
    game_id = cursor.lastrowid
    db.commit()

    return jsonify({'game_id': game_id, 'wallet_balance': new_balance, 'status': 'playing'})

@app.route('/api/games/flip/flip/', methods=['POST'])
@token_required
def flip_flip():
    user_id = request.user['user_id']
    data = request.json
    game_id = data.get('game_id')
    choice = data.get('choice')

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM flip_games WHERE id = ? AND user_id = ?', (game_id, user_id))
    game = cursor.fetchone()

    if not game: return jsonify({'detail': 'Game not found.'}), 404
    if game['status'] != 'playing': return jsonify({'detail': 'Game is over.'}), 400

    outcome = 'heads' if random.random() < 0.5 else 'tails'
    is_win = (outcome == choice)

    if not is_win:
        cursor.execute('UPDATE flip_games SET status = "exploded" WHERE id = ?', (game['id'],))
        db.commit()
        return jsonify({'status': 'exploded', 'outcome': outcome})
    else:
        multi = 1.50 if game['multiplier'] == 1.00 else game['multiplier'] * 1.50
        cursor.execute('UPDATE flip_games SET multiplier = ? WHERE id = ?', (multi, game['id']))
        db.commit()
        return jsonify({'status': 'safe', 'outcome': outcome, 'multiplier': multi})

@app.route('/api/games/flip/cashout/', methods=['POST'])
@token_required
def flip_cashout():
    user_id = request.user['user_id']
    data = request.json
    game_id = data.get('game_id')

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM flip_games WHERE id = ? AND user_id = ?', (game_id, user_id))
    game = cursor.fetchone()

    if not game: return jsonify({'detail': 'Game not found.'}), 404
    if game['status'] != 'playing': return jsonify({'detail': 'Game over.'}), 400
    if game['multiplier'] <= 1.00: return jsonify({'detail': 'Must play 1 round.'}), 400

    payout = game['bet_amount'] * game['multiplier']
    cursor.execute('UPDATE flip_games SET status = "cashed_out" WHERE id = ?', (game['id'],))
    cursor.execute('UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?', (payout, user_id))
    db.commit()

    cursor.execute('SELECT wallet_balance FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    return jsonify({'status': 'cashed_out', 'payout': payout, 'wallet_balance': user['wallet_balance']})

# --- GAME: CHICKEN RUN ---
chicken_config = {
    'easy': {'lanes': 20, 'prob': 0.92},
    'medium': {'lanes': 15, 'prob': 0.86},
    'hard': {'lanes': 10, 'prob': 0.70}
}
def get_chicken_multiplier(prob, steps):
    if steps == 0: return 0.00
    total_prob = prob ** steps
    multi = (1 / total_prob) * 0.99
    return math.floor(multi * 100) / 100

@app.route('/api/games/chicken/start/', methods=['POST'])
@token_required
def chicken_start():
    user_id = request.user['user_id']
    data = request.json
    bet_amount = float(data.get('bet', 0))
    difficulty = data.get('difficulty')

    if bet_amount < 0: return jsonify({'detail': 'Invalid bet.'}), 400
    if difficulty not in chicken_config: return jsonify({'detail': 'Invalid difficulty.'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT wallet_balance FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()

    if not user: return jsonify({'detail': 'Database error.'}), 500
    if user['wallet_balance'] < bet_amount and bet_amount > 0: return jsonify({'detail': 'Insufficient funds.'}), 400

    new_balance = user['wallet_balance'] - bet_amount
    cursor.execute('UPDATE users SET wallet_balance = ? WHERE id = ?', (new_balance, user_id))

    total_lanes = chicken_config[difficulty]['lanes']
    prob = chicken_config[difficulty]['prob']
    secret_path = [random.random() <= prob for _ in range(total_lanes)]

    cursor.execute('INSERT INTO chicken_games (user_id, bet_amount, difficulty, total_lanes, secret_path, current_step, status, multiplier) VALUES (?, ?, ?, ?, ?, 0, "playing", 0.00)',
                   (user_id, bet_amount, difficulty, total_lanes, json.dumps(secret_path)))
    game_id = cursor.lastrowid
    db.commit()

    return jsonify({'game_id': game_id, 'wallet_balance': new_balance, 'status': 'playing'})

@app.route('/api/games/chicken/jump/', methods=['POST'])
@token_required
def chicken_jump():
    user_id = request.user['user_id']
    data = request.json
    game_id = data.get('game_id')

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM chicken_games WHERE id = ? AND user_id = ?', (game_id, user_id))
    game = cursor.fetchone()

    if not game: return jsonify({'detail': 'Game not found.'}), 404
    if game['status'] != 'playing': return jsonify({'detail': 'Game is over.'}), 400

    secret_path = json.loads(game['secret_path'])
    next_step = game['current_step'] + 1

    if next_step > game['total_lanes']: return jsonify({'detail': 'Max step reached.'}), 400
    
    is_safe = secret_path[game['current_step']]

    if not is_safe:
        cursor.execute('UPDATE chicken_games SET status = "exploded" WHERE id = ?', (game['id'],))
        db.commit()
        return jsonify({'status': 'exploded'})
    else:
        prob = chicken_config[game['difficulty']]['prob']
        multi = get_chicken_multiplier(prob, next_step)

        if next_step == game['total_lanes']:
            payout = game['bet_amount'] * multi
            cursor.execute('UPDATE chicken_games SET current_step = ?, multiplier = ?, status = "cashed_out" WHERE id = ?', (next_step, multi, game['id']))
            cursor.execute('UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?', (payout, user_id))
            db.commit()
            cursor.execute('SELECT wallet_balance FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            return jsonify({'status': 'cashed_out', 'current_step': next_step, 'multiplier': multi, 'payout': payout, 'wallet_balance': user['wallet_balance']})
        else:
            cursor.execute('UPDATE chicken_games SET current_step = ?, multiplier = ? WHERE id = ?', (next_step, multi, game['id']))
            db.commit()
            return jsonify({'status': 'safe', 'current_step': next_step, 'multiplier': multi})

@app.route('/api/games/chicken/cashout/', methods=['POST'])
@token_required
def chicken_cashout():
    user_id = request.user['user_id']
    data = request.json
    game_id = data.get('game_id')

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM chicken_games WHERE id = ? AND user_id = ?', (game_id, user_id))
    game = cursor.fetchone()

    if not game: return jsonify({'detail': 'Game not found.'}), 404
    if game['status'] != 'playing': return jsonify({'detail': 'Game over.'}), 400
    if game['current_step'] == 0: return jsonify({'detail': 'Must jump 1 step minimum.'}), 400

    payout = game['bet_amount'] * game['multiplier']
    cursor.execute('UPDATE chicken_games SET status = "cashed_out" WHERE id = ?', (game['id'],))
    cursor.execute('UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?', (payout, user_id))
    db.commit()

    cursor.execute('SELECT wallet_balance FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    return jsonify({'status': 'cashed_out', 'payout': payout, 'wallet_balance': user['wallet_balance']})

# --- GAME: TIC TAC TOE ---
ttt_multipliers = {'easy': 1.5, 'medium': 2.0, 'hard': 5.0}
ttt_win_lines = [
    [0, 1, 2], [3, 4, 5], [6, 7, 8],
    [0, 3, 6], [1, 4, 7], [2, 5, 8],
    [0, 4, 8], [2, 4, 6]
]

def ttt_check_win(board):
    for line in ttt_win_lines:
        a, b, c = line
        if board[a] and board[a] == board[b] and board[a] == board[c]:
            return board[a]
    if None not in board:
        return 'draw'
    return None

def ttt_minimax(board, depth, is_max):
    result = ttt_check_win(board)
    if result == 'O': return 10 - depth
    if result == 'X': return depth - 10
    if result == 'draw': return 0

    best_score = -math.inf if is_max else math.inf
    for i in range(9):
        if board[i] is None:
            board[i] = 'O' if is_max else 'X'
            score = ttt_minimax(board, depth + 1, not is_max)
            board[i] = None
            best_score = max(score, best_score) if is_max else min(score, best_score)
    return best_score

def ttt_get_winning_or_blocking_move(board, symbol):
    for line in ttt_win_lines:
        a, b, c = line
        vals = [board[a], board[b], board[c]]
        if vals.count(symbol) == 2 and vals.count(None) == 1:
            return line[vals.index(None)]
    return None

def get_cpu_move(board, difficulty):
    empty_spaces = [i for i, v in enumerate(board) if v is None]
    if not empty_spaces: return -1

    if difficulty == 'easy':
        if random.random() < 0.2:
            move = ttt_get_winning_or_blocking_move(board, 'O') or ttt_get_winning_or_blocking_move(board, 'X')
            if move is not None: return move
        return random.choice(empty_spaces)
    elif difficulty == 'medium':
        move = ttt_get_winning_or_blocking_move(board, 'O') or ttt_get_winning_or_blocking_move(board, 'X')
        if move is not None: return move
        if board[4] is None: return 4
        return random.choice(empty_spaces)
    else:
        # hard
        best_score = -math.inf
        move = -1
        for i in range(9):
            if board[i] is None:
                board[i] = 'O'
                score = ttt_minimax(board, 0, False)
                board[i] = None
                if score > best_score:
                    best_score = score
                    move = i
        return move

@app.route('/api/games/tictactoe/start/', methods=['POST'])
@token_required
def ttt_start():
    user_id = request.user['user_id']
    data = request.json
    bet_amount = float(data.get('bet', 0))
    difficulty = data.get('difficulty')

    if bet_amount < 0: return jsonify({'detail': 'Invalid bet.'}), 400
    if bet_amount != 0 and not (50 <= bet_amount <= 100):
        return jsonify({'detail': 'Bet must be exactly ₹0.00, or between ₹50.00 and ₹100.00!'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT wallet_balance FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()

    if not user: return jsonify({'detail': 'Database error.'}), 500
    if user['wallet_balance'] < bet_amount and bet_amount > 0: return jsonify({'detail': 'Insufficient funds.'}), 400

    new_balance = user['wallet_balance'] - bet_amount
    cursor.execute('UPDATE users SET wallet_balance = ? WHERE id = ?', (new_balance, user_id))

    initial_board = [None] * 9
    cursor.execute('INSERT INTO tictactoe_games (user_id, bet_amount, difficulty, board, status) VALUES (?, ?, ?, ?, "playing")',
                   (user_id, bet_amount, difficulty, json.dumps(initial_board)))
    game_id = cursor.lastrowid
    db.commit()

    return jsonify({'game_id': game_id, 'wallet_balance': new_balance, 'status': 'playing'})

@app.route('/api/games/tictactoe/move/', methods=['POST'])
@token_required
def ttt_move():
    user_id = request.user['user_id']
    data = request.json
    game_id = data.get('game_id')
    spot_idx = int(data.get('spot_idx'))

    if spot_idx < 0 or spot_idx > 8: return jsonify({'detail': 'Invalid move.'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM tictactoe_games WHERE id = ? AND user_id = ?', (game_id, user_id))
    game = cursor.fetchone()

    if not game: return jsonify({'detail': 'Game not found.'}), 404
    if game['status'] != 'playing': return jsonify({'detail': 'Game over.'}), 400

    board = json.loads(game['board'])
    if board[spot_idx] is not None: return jsonify({'detail': 'Spot taken.'}), 400

    board[spot_idx] = 'X'

    state = ttt_check_win(board)
    if state == 'X':
        payout = game['bet_amount'] * ttt_multipliers[game['difficulty']]
        cursor.execute('UPDATE tictactoe_games SET board = ?, status = "win" WHERE id = ?', (json.dumps(board), game['id']))
        cursor.execute('UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?', (payout, user_id))
        db.commit()
        return jsonify({'status': 'win', 'board': board, 'payout': payout})
    elif state == 'draw':
        payout = game['bet_amount']
        cursor.execute('UPDATE tictactoe_games SET board = ?, status = "draw" WHERE id = ?', (json.dumps(board), game['id']))
        cursor.execute('UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?', (payout, user_id))
        db.commit()
        return jsonify({'status': 'draw', 'board': board, 'payout': payout})

    cpu_move_idx = get_cpu_move(board, game['difficulty'])
    if cpu_move_idx != -1:
        board[cpu_move_idx] = 'O'

    state = ttt_check_win(board)
    if state == 'O':
        cursor.execute('UPDATE tictactoe_games SET board = ?, status = "loss" WHERE id = ?', (json.dumps(board), game['id']))
        db.commit()
        return jsonify({'status': 'loss', 'board': board, 'cpu_move': cpu_move_idx})
    elif state == 'draw':
        payout = game['bet_amount']
        cursor.execute('UPDATE tictactoe_games SET board = ?, status = "draw" WHERE id = ?', (json.dumps(board), game['id']))
        cursor.execute('UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?', (payout, user_id))
        db.commit()
        return jsonify({'status': 'draw', 'board': board, 'payout': payout, 'cpu_move': cpu_move_idx})

    cursor.execute('UPDATE tictactoe_games SET board = ? WHERE id = ?', (json.dumps(board), game['id']))
    db.commit()
    return jsonify({'status': 'playing', 'board': board, 'cpu_move': cpu_move_idx})

if __name__ == '__main__':
    print("🚀 Python Flask Backend starting on port 8000...")
    # Running on 8000 ensures frontend won't have to change URLs
    app.run(host='127.0.0.1', port=8000, debug=True)
