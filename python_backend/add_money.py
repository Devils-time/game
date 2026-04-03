import sqlite3
import sys

db_path = './database.sqlite'

if len(sys.argv) < 3:
    print("Usage: python add_money.py <username> <amount>")
    sys.exit(1)

username = sys.argv[1]
amount = float(sys.argv[2])

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute('SELECT username, wallet_balance FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    
    if not user:
        print(f"Error: User '{username}' not found.")
        sys.exit(1)
        
    cursor.execute('UPDATE users SET wallet_balance = wallet_balance + ? WHERE username = ?', (amount, username))
    conn.commit()
    
    # Fetch new balance
    cursor.execute('SELECT wallet_balance FROM users WHERE username = ?', (username,))
    new_balance = cursor.fetchone()[0]
    
    print(f"Success! Added {amount} to {username}. New balance: {new_balance}")
    
finally:
    if conn:
        conn.close()
