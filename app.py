import streamlit as st
from sqlalchemy.orm import sessionmaker
from models import User, Student, Result, engine
import pandas as pd
import bcrypt

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

# User login/signup
def login():
    st.sidebar.title("Login")
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")
    if st.sidebar.button("Login"):
        user = session.query(User).filter_by(username=username).first()
        if user and check_password(password, user.password):  # Corrected here
            st.session_state['user'] = user
            st.success(f"Welcome {user.username}!")
            return user
        else:
            st.error("Invalid username or password.")
    return None

def signup():
    st.sidebar.title("Signup")
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")
    role = st.sidebar.selectbox("Role", ["Teacher", "Parent"])
    if st.sidebar.button("Signup"):
        if session.query(User).filter_by(username=username).first():
            st.error("Username already exists.")
        else:
            hashed_pw = hash_password(password)
            new_user = User(username=username, password=hashed_pw, role=role)
            session.add(new_user)
            session.commit()
            st.success("Signup successful! Please log in.")

# Dashboard for teachers
def teacher_dashboard():
    st.title("Teacher Dashboard")
    action = st.radio("Choose Action", ["Upload Results", "View Results"])
    
    if action == "Upload Results":
        st.subheader("Upload Results")
        student_id = st.number_input("Student ID", min_value=1, step=1)
        subject = st.selectbox("Subject", SUBJECTS)
        marks = st.number_input("Marks", min_value=0, max_value=100, step=1)
        grade = st.text_input("Grade")
        
        if st.button("Upload"):
            result = Result(student_id=student_id, subject=subject, marks=marks, grade=grade)
            session.add(result)
            session.commit()
            st.success(f"Result for {subject} uploaded successfully!")
    
    elif action == "View Results":
        st.subheader("View All Results")
        results = session.query(Result).all()
        if results:
            data = [{"Student ID": r.student_id, "Subject": r.subject, "Marks": r.marks, "Grade": r.grade} for r in results]
            st.table(pd.DataFrame(data))
        else:
            st.info("No results uploaded yet.")

# Dashboard for parents
def parent_dashboard():
    st.title("Parent Dashboard")
    parent_id = st.session_state['user'].id
    students = session.query(Student).filter_by(parent_id=parent_id).all()
    if students:
        for student in students:
            st.subheader(f"Results for {student.name}")
            results = session.query(Result).filter_by(student_id=student.id).all()
            if results:
                data = [{"Subject": r.subject, "Marks": r.marks, "Grade": r.grade} for r in results]
                # Reorder data for display
                ordered_data = {subject: None for subject in SUBJECTS}
                for result in data:
                    ordered_data[result["Subject"]] = result
                final_data = [{"Subject": subject, "Marks": ordered_data[subject]["Marks"], "Grade": ordered_data[subject]["Grade"]} if ordered_data[subject] else {"Subject": subject, "Marks": "N/A", "Grade": "N/A"} for subject in SUBJECTS]
                st.table(pd.DataFrame(final_data))
            else:
                st.info("No results found for this student.")
    else:
        st.info("No results found for your children.")

# Main app logic
def main():
    if "user" not in st.session_state:
        st.session_state['user'] = None
    
    st.sidebar.title("Result Management System")
    if st.sidebar.checkbox("Already have an account?"):
        user = login()
    else:
        signup()
    
    if st.session_state['user']:
        user = st.session_state['user']
        if user.role == "Teacher":
            teacher_dashboard()
        elif user.role == "Parent":
            parent_dashboard()

if __name__ == "__main__":
    main()
