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

def logout():
    st.session_state['user'] = None
    st.session_state['is_logged_in'] = False
    st.success("You have been logged out.")

# User login/signup
def login():
    st.sidebar.title("Login")
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")
    if st.sidebar.button("Login"):
        user = session.query(User).filter_by(username=username).first()
        if user and check_password(password, user.password):
            st.session_state['user'] = user
            st.session_state['is_logged_in'] = True
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

# Unified result view
def view_results(student_id, student_name):
    student = session.query(Student).filter_by(id=student_id, name=student_name).first()
    if student:
        st.subheader(f"Results for {student.name}")
        results = session.query(Result).filter_by(student_id=student_id).all()
        if results:
            data = {subject: {"Marks": "N/A", "Grade": "N/A"} for subject in SUBJECTS}
            for result in results:
                data[result.subject] = {"Marks": result.marks, "Grade": result.grade}
            table_data = {
                "Student Name": [student.name],
                **{f"{subject} (Marks)": [data[subject]["Marks"]] for subject in SUBJECTS},
                **{f"{subject} (Grade)": [data[subject]["Grade"]] for subject in SUBJECTS},
            }
            st.table(pd.DataFrame(table_data))
        else:
            st.info(f"No results found for {student.name}.")
    else:
        st.error("Student ID and name do not match any records.")

# Teacher dashboard
def teacher_dashboard():
    st.title("Teacher Dashboard")
    action = st.radio("Choose Action", ["Upload Results", "View All Results"])

    if action == "Upload Results":
        st.subheader("Upload Results")
        student_name = st.text_input("Student Name")
        subject = st.selectbox("Subject", SUBJECTS)
        marks = st.number_input("Marks", min_value=0, max_value=100, step=1)
        grade = st.text_input("Grade")
        
        if st.button("Upload"):
            # Check if student exists by name
            student = session.query(Student).filter_by(name=student_name).first()
            if not student:
                # Automatically generate a new student ID if the student doesn't exist
                new_student_id = session.query(Student).count() + 1
                student = Student(id=new_student_id, name=student_name)
                session.add(student)
                session.commit()
                st.success(f"New student {student_name} added with ID {new_student_id}.")
            
            # Save the result
            result = Result(student_id=student.id, subject=subject, marks=marks, grade=grade)
            session.add(result)
            session.commit()
            st.success(f"Result for {subject} uploaded successfully for {student_name}!")

    elif action == "View All Results":
        st.subheader("All Student Results")
        students = session.query(Student).all()

        if students:
            table_data = []
            for student in students:
                student_results = session.query(Result).filter_by(student_id=student.id).all()
                data = {
                    "Student ID": student.id,
                    "Student Name": student.name,
                    **{f"{subject} (Marks)": "N/A" for subject in SUBJECTS},
                    **{f"{subject} (Grade)": "N/A" for subject in SUBJECTS},
                }
                for result in student_results:
                    data[f"{result.subject} (Marks)"] = result.marks
                    data[f"{result.subject} (Grade)"] = result.grade
                table_data.append(data)

            st.dataframe(pd.DataFrame(table_data))
        else:
            st.info("No results available.")

# Parent dashboard
def parent_dashboard():
    st.title("Parent Dashboard")
    student_id = st.number_input("Enter Student ID", min_value=1, step=1)
    student_name = st.text_input("Enter Student Name")
    if st.button("View Results"):
        view_results(student_id, student_name)

# Main app logic
def main():
    # Initialize session state
    if "user" not in st.session_state:
        st.session_state['user'] = None
    if "is_logged_in" not in st.session_state:
        st.session_state['is_logged_in'] = False

    st.sidebar.title("Result Management System")

    if st.session_state['is_logged_in']:
        if st.sidebar.button("Logout"):
            logout()
    else:
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
