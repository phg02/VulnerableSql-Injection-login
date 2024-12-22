from flask import Flask, render_template, request, url_for,redirect
import re
import sqlite3
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import Flask, session
from flask_session import Session
import html 
from bcrypt import hashpw, gensalt, checkpw  # Import bcrypt functions
import bleach

app = Flask(__name__)

app.secret_key = 'super_secure_key'
app.config['SESSION_COOKIE_SECURE'] = True  # Ensure cookies are transmitted securely
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
Session(app)


# Initialize Limiter with the app
limiter = Limiter(
    get_remote_address,  # Uses IP address to identify the requester
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Global rate limits
)

@app.route('/')
def hello_world():
    return render_template('signin.html');

@app.route('/signout')
def signout():
    session.pop('user', None)
    return redirect("/")



@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit requests to 5 per minute
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    else:
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Sanitize inputs with bleach
        cleanUsername = bleach.clean(username.strip(), tags=[], attributes={}, styles=[])
        cleanEmail = bleach.clean(email.strip(), tags=[], attributes={}, styles=[])
        cleanPassword = bleach.clean(password.strip(), tags=[], attributes={}, styles=[])

        try:
            # Hash the password using bcrypt
            hashedPassword = hashpw(cleanPassword.encode('utf-8'), gensalt())
            
            # Connect to the database
            conn = sqlite3.connect('login.db')
            cursor = conn.cursor()
            
            # Check if the email already exists in the database
            query = "SELECT * FROM users WHERE email = ?"
            cursor.execute(query, (cleanEmail,))
            user = cursor.fetchone()
            if user is not None:
                print("User already exists:", cleanEmail)
                return render_template('error.html', error="User already exists")
            
            # Insert the new user into the database with the hashed password
            query = "INSERT INTO users (email, password) VALUES (?, ?)"
            cursor.execute(query, (cleanEmail, hashedPassword))
            conn.commit()
            print("User registered:", cleanEmail)
            
            return render_template('signin.html', message="User registered successfully. Please sign in.")
        
        except sqlite3.Error as e:
            print("Database error:", e)
            return render_template('error.html', error="Database error")
        
        finally:
            # Close the database connection
            conn.close()
    
    

@app.route('/signin', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit for this specific route
def signin():
    email = request.form['email']
    password = request.form['password']
    # Connect to the SQLite database
    try:
        conn = sqlite3.connect('login.db')
        cursor = conn.cursor()
         
        cursor.execute(f"SELECT * FROM users WHERE email = '{email}' AND password = '{password}'")
        user = cursor.fetchall()  # Fetch records

        if user:
            print("Login successful for:", email)
            return render_template('site.html', users = user)  # Redirect to the main page
        else:
            print("Invalid credentials for:", email)
            return render_template('error.html', error="Invalid credentials")

    except sqlite3.Error as e:
        print("Database error:", e)
        return render_template('error.html', error="Database error")

    finally:
        cursor.close()
        conn.close()


# @app.route('/error/<string:error>')
# def error():
#     return render_template('error.html', error=error);

if __name__ == '__main__':
    app.run(debug=True)
    
