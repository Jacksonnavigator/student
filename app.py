import streamlit as st
from sqlalchemy.orm import sessionmaker
from models import User, Student, Result, engine
import pandas as pd
import bcrypt
import plotly.express as px
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import string
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Email Configuration
SENDER_EMAIL = "jacksonnavigator19@gmail.com"
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")  # Store securely in .env
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# Database session
Session = sessionmaker(bind=engine)
session = Session()

# Predefined subjects
SUBJECTS = [
    "Mathematics", "English", "Geography", "History",
    "Physics", "Chemistry", "Biology", "Civics", "Kiswahili"
]

# Helper functions
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def logout():
    st.session_state['user'] = None
    st.session_state['is_logged_in'] = False
    st.success("You have been logged out.")

# Email Utility
def send_recovery_email(recipient_email, token):
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = recipient_email
        msg['Subject'] = "Password Recovery"

        body = f"Your password recovery token is: {token}\n\nUse this token to reset your password."
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())
        server.quit()
        st.success("Recovery email sent successfully!")
    except Exception as e:
        st.error(f"Error sending email: {str(e)}")

# Generate Token
def generate_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

# Password Recovery
def password_recovery():
    st.sidebar.title("🔑 Password Recovery")
    email = st.sidebar.text_input("Enter your registered email")

    if st.sidebar.button("Send Recovery Email"):
        user = session.query(User).filter_by(email=email).first()
        if user:
            token = generate_token()
            user.recovery_token = token
            session.commit()
            send_recovery_email(email, token)
        else:
            st.error("Email not found in the system.")

def reset_password():
    st.sidebar.title("🔑 Reset Password")
    email = st.sidebar.text_input("Enter your registered email")
    token = st.sidebar.text_input("Enter the recovery token")
    new_password = st.sidebar.text_input("Enter new password", type="password")

    if st.sidebar.button("Reset Password"):
        user = session.query(User).filter_by(email=email, recovery_token=token).first()
        if user:
            user.password = hash_password(new_password)
            user.recovery_token = None  # Clear token after successful reset
            session.commit()
            st.success("Password reset successful! Please log in.")
        else:
            st.error("Invalid email or token.")

# User login/signup
def login():
    st.sidebar.title("🔒 Login")
    st.sidebar.markdown("Access your dashboard based on your role.")
    username = st.sidebar.text_input("👤 Username")
    password = st.sidebar.text_input("🔑 Password", type="password")
    if st.sidebar.button("Login", type="primary"):
        user = session.query(User).filter_by(username=username).first()
        if user and check_password(password, user.password):
            st.session_state['user'] = user
            st.session_state['is_logged_in'] = True
            st.success(f"🎉 Welcome, {user.username}!")
            return user
        else:
            st.error("❌ Invalid username or password.")
    st.sidebar.markdown("Forgot your password? [Recover it](#)", unsafe_allow_html=True)
    return None

def signup():
    st.sidebar.title("📝 Signup")
    st.sidebar.markdown("Create a new account to access the system.")
    username = st.sidebar.text_input("👤 Username")
    email = st.sidebar.text_input("📧 Email")
    password = st.sidebar.text_input("🔑 Password", type="password")
    role = st.sidebar.selectbox("👥 Role", ["Teacher", "Parent"])
    if st.sidebar.button("Signup", type="primary"):
        if session.query(User).filter_by(username=username).first():
            st.error("❌ Username already exists.")
        elif session.query(User).filter_by(email=email).first():
            st.error("❌ Email already registered.")
        else:
            hashed_pw = hash_password(password)
            new_user = User(username=username, email=email, password=hashed_pw, role=role)
            session.add(new_user)
            session.commit()
            st.success("🎉 Signup successful! Please log in.")

# Main app logic
def main():
    if "user" not in st.session_state:
        st.session_state['user'] = None
    if "is_logged_in" not in st.session_state:
        st.session_state['is_logged_in'] = False

    st.sidebar.title("🎓 Result Management System")

    if st.session_state['is_logged_in']:
        if st.sidebar.button("Logout", type="secondary"):
            logout()
    else:
        if st.sidebar.checkbox("Already have an account?"):
            user = login()
        else:
            signup()
        st.sidebar.markdown("Forgot password? [Recover it](#)", unsafe_allow_html=True)
        password_recovery()
        reset_password()

    if st.session_state['user']:
        user = st.session_state['user']
        if user.role == "Teacher":
            teacher_dashboard()
        elif user.role == "Parent":
            parent_dashboard()

if __name__ == "__main__":
    main()
