import hashlib
from flask import Flask, render_template, request, redirect, url_for
from flask_mysqldb import MySQL
import os
import base64

# Password Complexity Check
def password_validation(password):
    if len(password) < 10:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c in '!@#$%^&*()-_+=' for c in password):
        return False
    return True

# Utility functions for salt and password hashing
def generate_salt():
    return base64.b64encode(os.urandom(16)).decode('utf-8')

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()

app = Flask(__name__)

# Database Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
#app.config['MYSQL_PASSWORD'] = 'Id@645789'
app.config['MYSQL_PASSWORD'] = '8822'
app.config['MYSQL_DB'] = 'myappdb'

mysql = MySQL(app)

def create_table():
    with app.app_context():
        try:
            cur = mysql.connection.cursor()
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) NOT NULL,
                    email VARCHAR(100) NOT NULL UNIQUE,
                    password VARCHAR(255) NOT NULL,
                    salt VARCHAR(255) NOT NULL
                );
            ''')
            mysql.connection.commit()
            cur.close()
            print("✅ 'users' table is ready!")
        except Exception as e:
            print(f"❌ Error creating table: {str(e)}")


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT password, salt FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            cur.close()

            if user:
                stored_hash, stored_salt = user
                entered_hash = hash_password(password, stored_salt)

                if entered_hash == stored_hash:
                    return redirect(url_for('dashboard'))
                else:
                    return render_template('LoginPage.html', error="Invalid credentials")
            else:
                return render_template('LoginPage.html', error="User not found")

        except Exception as e:
            return render_template('LoginPage.html', error=f"Error: {str(e)}")

    return render_template('LoginPage.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if not password_validation(password):
            return render_template('RegisterPage.html',
                                   error="Password must be at least 10 characters long, include an uppercase letter, a lowercase letter, a number, and a special character.")

        salt = generate_salt()
        hashed_password = hash_password(password, salt)

        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO users (username, email, password, salt) VALUES (%s, %s, %s, %s)",
                        (username, email, hashed_password, salt))
            mysql.connection.commit()
            cur.close()
            return redirect(url_for('login'))
        except Exception as e:
            return render_template('RegisterPage.html', error=f"Error: {str(e)}")

    return render_template('RegisterPage.html')


@app.route('/dashboard')
def dashboard():
    user_data = {
        'username': 'admin',
        'email': 'admin@example.com',
        'member_since': 'January 2023'
    }
    return render_template('dashboard.html', **user_data)


if __name__ == '__main__':
    print("🚀 Connecting to MySQL...")
    create_table()  # Ensure table exists before running Flask
    print("🚀 Running Flask on http://127.0.0.1:5000/")
    app.run(debug=True)
