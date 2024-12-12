import streamlit as st
from sqlalchemy.orm import sessionmaker
from models import User, Student, Result, engine
import pandas as pd
import bcrypt
import plotly.express as px

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
    st.sidebar.title("\U0001F512 Login")  # Unicode for 🔒 emoji
    username = st.sidebar.text_input("\U0001F464 Username")  # Unicode for 👤 emoji
    password = st.sidebar.text_input("\U0001F50D Password", type="password")  # Unicode for 🔍 emoji

    if st.sidebar.button("Login", type="primary"):
        user = session.query(User).filter_by(username=username).first()
        if user and check_password(password, user.password):
            st.session_state['user'] = user
            st.session_state['is_logged_in'] = True
            st.success(f"\U0001F389 Welcome, {user.username}!")  # Unicode for 🎉 emoji
        else:
            st.error("\u274C Invalid username or password.")  # Unicode for ❌ emoji

    if st.sidebar.button("Forgot Password?"):
        recover_password()

def signup():
    st.sidebar.title("\U0001F4CB Signup")  # Unicode for 📋 emoji
    username = st.sidebar.text_input("\U0001F464 Username")  # Unicode for 👤 emoji
    password = st.sidebar.text_input("\U0001F50D Password", type="password")  # Unicode for 🔍 emoji
    role = st.sidebar.selectbox("\U0001F465 Role", ["Teacher", "Parent"])  # Unicode for 👥 emoji
    security_question = st.sidebar.text_input("\U0001F6E1 Security Question")  # Unicode for ⚡ emoji
    security_answer = st.sidebar.text_input("\U0001F50D Security Answer")  # Unicode for 🔍 emoji

    if st.sidebar.button("Signup", type="primary"):
        if session.query(User).filter_by(username=username).first():
            st.error("\u274C Username already exists.")  # Unicode for ❌ emoji
        else:
            hashed_pw = hash_password(password)
            hashed_answer = hash_password(security_answer)
            new_user = User(
                username=username,
                password=hashed_pw,
                role=role,
                security_question=security_question,
                security_answer=hashed_answer
            )
            session.add(new_user)
            session.commit()
            st.success("\U0001F389 Signup successful! Please log in.")  # Unicode for 🎉 emoji

# Password recovery
def recover_password():
    st.title("\U0001F512 Recover Password")  # Unicode for 🔒 emoji
    username = st.text_input("\U0001F464 Enter your Username")  # Unicode for 👤 emoji
    user = session.query(User).filter_by(username=username).first()

    if user:
        st.write(f"\U0001F6E1 Security Question: {user.security_question}")  # Unicode for ⚡ emoji
        security_answer = st.text_input("\U0001F50D Answer", type="password")  # Unicode for 🔍 emoji
        new_password = st.text_input("\U0001F512 New Password", type="password")  # Unicode for 🔒 emoji

        if st.button("Submit"):
            if check_password(security_answer, user.security_answer):
                hashed_pw = hash_password(new_password)
                user.password = hashed_pw
                session.commit()
                st.success("\U0001F389 Password successfully updated! You can now log in.")  # Unicode for 🎉 emoji
            else:
                st.error("\u274C Incorrect security answer.")  # Unicode for ❌ emoji
    else:
        st.error("\u274C User not found.")  # Unicode for ❌ emoji

# Unified result view
def view_results(student_id, student_name):
    student = session.query(Student).filter_by(id=student_id, name=student_name).first()
    if student:
        st.subheader(f"\U0001F4DD Results for {student.name}")  # Unicode for 📝 emoji
        results = session.query(Result).filter_by(student_id=student_id).all()
        if results:
            data = {subject: {"Marks": "N/A", "Grade": "N/A"} for subject in SUBJECTS}
            for result in results:
                data[result.subject] = {"Marks": result.marks, "Grade": result.grade}

            table_data = {
                "Subject": list(data.keys()),
                "Marks": [data[subject]["Marks"] for subject in SUBJECTS],
                "Grade": [data[subject]["Grade"] for subject in SUBJECTS]
            }

            df = pd.DataFrame(table_data)
            st.table(df)

            # Add download button
            csv = df.to_csv(index=False)
            st.download_button(
                label="\U0001F4C5 Download Results as CSV",  # Unicode for 📅 emoji
                data=csv,
                file_name=f"{student.name}_results.csv",
                mime="text/csv"
            )

            # Add performance trend button
            if st.button("\U0001F4CA View Performance Trend"):  # Unicode for 📊 emoji
                plot_performance_trend(df)
        else:
            st.info(f"\U2139\ufe0f No results found for {student.name}.")  # Unicode for ℹ️ emoji
    else:
        st.error("\u274C Student ID and name do not match any records.")  # Unicode for ❌ emoji

def plot_performance_trend(df):
    st.subheader("\U0001F4CA Performance Trend")  # Unicode for 📊 emoji
    if "Marks" in df.columns and "Subject" in df.columns:
        fig = px.bar(df, x="Subject", y="Marks", title="Student Performance by Subject",
                     labels={"Marks": "Marks", "Subject": "Subjects"},
                     text_auto=True)
        st.plotly_chart(fig)
    else:
        st.error("\u274C Insufficient data to plot performance trend.")  # Unicode for ❌ emoji

# Teacher dashboard
def teacher_dashboard():
    st.title("\U0001F4DA Teacher Dashboard")  # Unicode for 📚 emoji
    action = st.radio("Choose Action", ["Upload Results", "View All Results"], index=0)

    if action == "Upload Results":
        st.subheader("\U270D Upload Results")  # Unicode for ✍ emoji
        student_name = st.text_input("Student Name")
        subject = st.selectbox("Subject", SUBJECTS)
        marks = st.number_input("Marks", min_value=0, max_value=100, step=1)
        grade = st.text_input("Grade")

        if st.button("Upload", type="primary"):
            student = session.query(Student).filter_by(name=student_name).first()
            if not student:
                new_student_id = session.query(Student).count() + 1
                student = Student(id=new_student_id, name=student_name)
                session.add(student)
                session.commit()
                st.success(f"\U2728 New student {student_name} added with ID {new_student_id}.")  # Unicode for ✨ emoji

            result = Result(student_id=student.id, subject=subject, marks=marks, grade=grade)
            session.add(result)
            session.commit()
            st.success(f"\U2705 Result for {subject} uploaded successfully for {student_name}!")  # Unicode for ✅ emoji

    elif action == "View All Results":
        st.subheader("\U0001F4CD All Student Results")  # Unicode for 📍 emoji
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
            st.info("\U2139\ufe0f No results available.")  # Unicode for ℹ️ emoji

# Parent dashboard
def parent_dashboard():
    st.title("\U0001F468\U0000200D\U0001F469\U0000200D\U0001F466 Parent Dashboard")  # Unicode for 👨‍👩‍👧 emoji
    student_id = st.number_input("Enter Student ID", min_value=1, step=1)
    student_name = st.text_input("Enter Student Name")
    if st.button("View Results", type="primary"):
        view_results(student_id, student_name)

# Main app logic
def main():
    if "user" not in st.session_state:
        st.session_state['user'] = None
    if "is_logged_in" not in st.session_state:
        st.session_state['is_logged_in'] = False

    st.sidebar.title("\U0001F393 Result Management System")  # Unicode for 🎓 emoji

    if st.session_state['is_logged_in']:
        if st.sidebar.button("Logout", type="secondary"):
            logout()
    else:
        if st.sidebar.checkbox("Already have an account?"):
            login()
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
