import streamlit as st
from sqlalchemy.orm import sessionmaker
from models import User, Student, Result, engine
import pandas as pd
import bcrypt
import plotly.express as px
import uuid

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

# Password recovery
def recover_password():
    st.sidebar.title("🔑 Recover Password")
    email = st.sidebar.text_input("📧 Enter your email address")
    if st.sidebar.button("Send Recovery Email"):
        user = session.query(User).filter_by(email=email).first()
        if user:
            token = str(uuid.uuid4())
            user.reset_token = token
            session.commit()
            st.success(f"A recovery email has been sent to {email} (Simulated). Token: {token}")
            # Simulate sending email (replace with real email-sending logic)
        else:
            st.error("Email address not found.")

def reset_password():
    st.sidebar.title("🔄 Reset Password")
    email = st.sidebar.text_input("📧 Enter your email address")
    token = st.sidebar.text_input("🔑 Enter recovery token")
    new_password = st.sidebar.text_input("🔒 Enter new password", type="password")
    if st.sidebar.button("Reset Password"):
        user = session.query(User).filter_by(email=email, reset_token=token).first()
        if user:
            user.password = hash_password(new_password)
            user.reset_token = None  # Invalidate the token
            session.commit()
            st.success("Your password has been reset successfully!")
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
        else:
            hashed_pw = hash_password(password)
            new_user = User(username=username, email=email, password=hashed_pw, role=role)
            session.add(new_user)
            session.commit()
            st.success("🎉 Signup successful! Please log in.")

# Grading system
def get_grade(marks):
    if marks >= 75:
        return "A"
    elif marks >= 65:
        return "B"
    elif marks >= 50:
        return "C"
    elif marks >= 30:
        return "D"
    else:
        return "F"

# Unified result view
def view_results(student_id, student_name):
    student = session.query(Student).filter_by(id=student_id, name=student_name).first()
    if student:
        st.subheader(f"📄 Results for {student.name}")
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
                label="📥 Download Results as CSV",
                data=csv,
                file_name=f"{student.name}_results.csv",
                mime="text/csv"
            )

            # Add performance trend button
            if st.button("📊 View Performance Trend"):
                plot_performance_trend(df)
        else:
            st.info(f"ℹ️ No results found for {student.name}.")
    else:
        st.error("❌ Student ID and name do not match any records.")

def plot_performance_trend(df):
    st.subheader("📊 Performance Trend")
    if "Marks" in df.columns and "Subject" in df.columns:
        fig = px.bar(df, x="Subject", y="Marks", title="Student Performance by Subject", 
                     labels={"Marks": "Marks", "Subject": "Subjects"}, 
                     text_auto=True)
        st.plotly_chart(fig)
    else:
        st.error("❌ Insufficient data to plot performance trend.")

# Teacher dashboard
def teacher_dashboard():
    st.title("📚 Teacher Dashboard")
    st.markdown("Manage student results and monitor their progress.")
    action = st.radio("Choose Action", ["Upload Results", "View All Results"], index=0)

    if action == "Upload Results":
        st.subheader("🖋 Upload Results")
        student_id = st.number_input("Student ID", min_value=1, step=1)
        student_name = st.text_input("Student Name")
        subject = st.selectbox("Subject", SUBJECTS)
        marks = st.number_input("Marks", min_value=0, max_value=100, step=1)
        grade = get_grade(marks)  # Automatically assign grade based on marks

        if st.button("Upload", type="primary"):
            student = session.query(Student).filter_by(name=student_name).first()
            if not student:
                new_student_id = session.query(Student).count() + 1
                student = Student(id=new_student_id, name=student_name)
                session.add(student)
                session.commit()
                st.success(f"✨ New student {student_name} added with ID {new_student_id}.")

            result = Result(student_id=student.id, subject=subject, marks=marks, grade=grade)
            session.add(result)
            session.commit()
            st.success(f"✅ Result for {subject} uploaded successfully for {student_name}!")

    elif action == "View All Results":
        st.subheader("📋 All Student Results")
        results = (
            session.query(Result.id, Student.name, Result.subject, Result.marks, Result.grade)
            .join(Student, Result.student_id == Student.id)
            .all()
        )
        
        if results:
            # Organize the data into a list of tuples
            data = []
            for result in results:
                data.append({
                    "Student Name": result.name,
                    "Subject": result.subject,
                    "Marks": result.marks,
                    "Grade": result.grade
                })

            # Create a DataFrame from the data list
            df = pd.DataFrame(data)

            # Display the results in a table format
            st.dataframe(df)
        else:
            st.info("ℹ️ No results available.")

# Parent dashboard
def parent_dashboard():
    st.title("👨‍👩‍👦 Parent Dashboard")
    st.markdown("View, download, and analyze your child's academic progress.")
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

    st.sidebar.title("🎓 Result Management System")

    if st.session_state['is_logged_in']:
        if st.sidebar.button("Logout", type="secondary"):
            logout()
    else:
        if st.sidebar.checkbox("Already have an account?"):
            user = login()
        elif st.sidebar.checkbox("Forgot Password?"):
            recover_password()
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
