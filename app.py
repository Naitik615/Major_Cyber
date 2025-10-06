from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt
import time

app = Flask(__name__)
app.secret_key = 'b7e0f3a1c5d94e2f8a3b0d7e9c4f1a2b'  

invalid_tokens = set()

# database
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            lock_until REAL DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

# Home page
@app.route('/')
def home():
    return render_template('home.html')

# Signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        if len(username) < 3 or len(password) < 4:
            return "Username or password too short."

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
            conn.commit()
            conn.close()
            return redirect('/login')
        except sqlite3.IntegrityError:
            return "Username already exists."

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT password, failed_attempts, lock_until FROM users WHERE username = ?", (username,))
        row = c.fetchone()

        if not row:
            conn.close()
            return "Invalid username or password."

        stored_hash, failed_attempts, lock_until = row

        now = time.time()
        
        if lock_until and now < lock_until:
            conn.close()
            return "Account is locked due to multiple failed attempts. Try again later."


        if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            c.execute("UPDATE users SET failed_attempts = 0, lock_until = 0 WHERE username = ?", (username,))
            conn.commit()
            conn.close()


            
            session.clear()
            session['username'] = username
            session['session_token'] = str(time.time()) 
            return redirect('/dashboard')

        else:

            failed_attempts += 1
            lock_time = 0
            if failed_attempts >= 5:
                lock_time = now + 300  

            c.execute("UPDATE users SET failed_attempts = ?, lock_until = ? WHERE username = ?",
                      (failed_attempts, lock_time, username))
            conn.commit()
            conn.close()
            return "Invalid credentials. Account will lock after 5 failed attempts."

    return render_template('login.html')

# Dashboard page 
@app.route('/dashboard')
def dashboard():
    if 'username' in session and 'session_token' in session:
        if session['session_token'] in invalid_tokens:
            session.clear()
            return redirect('/login')
        return render_template('dashboard.html', username=session['username'])
    else:
        return redirect('/login')

# Logout 
@app.route('/logout')
def logout():
    if 'session_token' in session:
        invalid_tokens.add(session['session_token'])
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
