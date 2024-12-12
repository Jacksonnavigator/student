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
    st.sidebar.title("\ud83d\udd12 Login")
    username = st.sidebar.text_input("\ud83d\udc64 Username")
    password = st.sidebar.text_input("\ud83d\udd11 Password", type="password")

    if st.sidebar.button("Login", type="primary"):
        user = session.query(User).filter_by(username=username).first()
        if user and check_password(password, user.password):
            st.session_state['user'] = user
            st.session_state['is_logged_in'] = True
            st.success(f"\ud83c\udf89 Welcome, {user.username}!")
        else:
            st.error("\u274c Invalid username or password.")

    if st.sidebar.button("Forgot Password?"):
        recover_password()

def signup():
    st.sidebar.title("\ud83d\uddcb Signup")
    username = st.sidebar.text_input("\ud83d\udc64 Username")
    password = st.sidebar.text_input("\ud83d\udd11 Password", type="password")
    role = st.sidebar.selectbox("\ud83d\udc65 Role", ["Teacher", "Parent"])
    security_question = st.sidebar.text_input("\ud83d\udee1 Security Question")
    security_answer = st.sidebar.text_input("\ud83d\udd11 Security Answer")

    if st.sidebar.button("Signup", type="primary"):
        if session.query(User).filter_by(username=username).first():
            st.error("\u274c Username already exists.")
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
            st.success("\ud83c\udf89 Signup successful! Please log in.")

# Password recovery
def recover_password():
    st.title("\ud83d\udd12 Recover Password")
    username = st.text_input("\ud83d\udc64 Enter your Username")
    user = session.query(User).filter_by(username=username).first()

    if user:
        st.write(f"\ud83d\udee1 Security Question: {user.security_question}")
        security_answer = st.text_input("\ud83d\udd11 Answer", type="password")
        new_password = st.text_input("\ud83d\udd12 New Password", type="password")

        if st.button("Submit"):
            if check_password(security_answer, user.security_answer):
                hashed_pw = hash_password(new_password)
                user.password = hashed_pw
                session.commit()
                st.success("\ud83c\udf89 Password successfully updated! You can now log in.")
            else:
                st.error("\u274c Incorrect security answer.")
    else:
        st.error("\u274c User not found.")

# Unified result view
def view_results(student_id, student_name):
    student = session.query(Student).filter_by(id=student_id, name=student_name).first()
    if student:
        st.subheader(f"\ud83d\udcdd Results for {student.name}")
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
                label="\ud83d\udcc5 Download Results as CSV",
                data=csv,
                file_name=f"{student.name}_results.csv",
                mime="text/csv"
            )

            # Add performance trend button
            if st.button("\ud83d\udcca View Performance Trend"):
                plot_performance_trend(df)
        else:
            st.info(f"\u2139\ufe0f No results found for {student.name}.")
    else:
        st.error("\u274c Student ID and name do not match any records.")

def plot_performance_trend(df):
    st.subheader("\ud83d\udcca Performance Trend")
    if "Marks" in df.columns and "Subject" in df.columns:
        fig = px.bar(df, x="Subject", y="Marks", title="Student Performance by Subject",
                     labels={"Marks": "Marks", "Subject": "Subjects"},
                     text_auto=True)
        st.plotly_chart(fig)
    else:
        st.error("\u274c Insufficient data to plot performance trend.")

# Teacher dashboard
def teacher_dashboard():
    st.title("\ud83d\udcda Teacher Dashboard")
    action = st.radio("Choose Action", ["Upload Results", "View All Results"], index=0)

    if action == "Upload Results":
        st.subheader("\u270d Upload Results")
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
                st.success(f"\u2728 New student {student_name} added with ID {new_student_id}.")

            result = Result(student_id=student.id, subject=subject, marks=marks, grade=grade)
            session.add(result)
            session.commit()
            st.success(f"\u2705 Result for {subject} uploaded successfully for {student_name}!")

    elif action == "View All Results":
        st.subheader("\ud83d\udccb All Student Results")
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
            st.info("\u2139\ufe0f No results available.")

# Parent dashboard
def parent_dashboard():
    st.title("\ud83d\udc68\u200d\ud83d\udc69\u200d\ud83d\udc66 Parent Dashboard")
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

    st.sidebar.title("\ud83c\udf93 Result Management System")

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
