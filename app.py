import streamlit as st
from sqlalchemy.orm import sessionmaker
from models import User, Student, Result, engine
import pandas as pd
import bcrypt
from fpdf import FPDF
import matplotlib.pyplot as plt
import time

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

def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not any(char.isdigit() for char in password):
        return "Password must include at least one number."
    if not any(char.isupper() for char in password):
        return "Password must include at least one uppercase letter."
    if not any(char.islower() for char in password):
        return "Password must include at least one lowercase letter."
    if not any(char in "!@#$%^&*()-_=+{}[]|;:'\",.<>?/`~" for char in password):
        return "Password must include at least one special character."
    return None

def check_session_timeout():
    if "last_active" in st.session_state:
        if time.time() - st.session_state['last_active'] > 300:  # 5 minutes
            logout()
    st.session_state['last_active'] = time.time()

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
            password_error = validate_password(password)
            if password_error:
                st.error(password_error)
            else:
                hashed_pw = hash_password(password)
                new_user = User(username=username, password=hashed_pw, role=role)
                session.add(new_user)
                session.commit()
                st.success("Signup successful! Please log in.")

# Unified result view
def view_results(student_id, student_name):
    try:
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
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")

# Teacher dashboard
def teacher_dashboard():
    st.title("Teacher Dashboard")
    tab1, tab2 = st.tabs(["Upload Results", "View All Results"])

    with tab1:
        st.subheader("Upload Results")
        student_id = st.number_input("Student Id
        student_name = st.text_input("Student Name")
        subject = st.selectbox("Subject", SUBJECTS)
        marks = st.number_input("Marks", min_value=0, max_value=100, step=1)
        grade = st.text_input("Grade")

        if st.button("Upload"):
            try:
                student = session.query(Student).filter_by(name=student_name).first()
                if not student:
                    new_student_id = session.query(Student).count() + 1
                    student = Student(id=new_student_id, name=student_name)
                    session.add(student)
                    session.commit()
                    st.success(f"New student {student_name} added with ID {new_student_id}.")

                result = Result(student_id=student.id, subject=subject, marks=marks, grade=grade)
                session.add(result)
                session.commit()
                st.success(f"Result for {subject} uploaded successfully for {student_name}!")
            except Exception as e:
                st.error(f"An error occurred: {str(e)}")

    with tab2:
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

# Bulk upload for results
def bulk_upload():
    uploaded_file = st.file_uploader("Upload CSV", type=["csv"])
    if uploaded_file:
        try:
            df = pd.read_csv(uploaded_file)
            for _, row in df.iterrows():
                student_name = row['Student Name']
                subject = row['Subject']
                marks = row['Marks']
                grade = row['Grade']

                student = session.query(Student).filter_by(name=student_name).first()
                if not student:
                    new_student_id = session.query(Student).count() + 1
                    student = Student(id=new_student_id, name=student_name)
                    session.add(student)
                    session.commit()

                result = Result(student_id=student.id, subject=subject, marks=marks, grade=grade)
                session.add(result)
            session.commit()
            st.success("Results uploaded successfully!")
        except Exception as e:
            st.error(f"Error uploading file: {str(e)}")

# Parent dashboard
def parent_dashboard():
    st.title("Parent Dashboard")
    student_id = st.number_input("Enter Student ID", min_value=1, step=1)
    student_name = st.text_input("Enter Student Name")
    if st.button("View Results"):
        view_results(student_id, student_name)

    if st.button("View Performance Trend"):
        plot_performance(student_id)

    if st.button("Generate PDF"):
        generate_pdf(student_id, student_name)

# Performance trend plot
def plot_performance(student_id):
    results = session.query(Result).filter_by(student_id=student_id).all()
    if results:
        subjects = [result.subject for result in results]
        marks = [result.marks for result in results]

        plt.figure(figsize=(10, 5))
        plt.bar(subjects, marks, color='skyblue')
        plt.xlabel("Subjects")
        plt.ylabel("Marks")
        plt.title("Performance Trend")
        st.pyplot(plt)
    else:
        st.info("No results available for trend analysis.")

# PDF generation
def generate_pdf(student_id, student_name):
    results = session.query(Result).filter_by(student_id=student_id).all()
    if results:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt=f"Results for {student_name}", ln=True, align='C')

        for result in results:
            pdf.cell(200, 10, txt=f"{result.subject}: {result.marks} ({result.grade})", ln=True)

        pdf.output(f"{student_name}_results.pdf")
        st.success("PDF generated!")
    else:
        st.info("No results to export.")

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

    check_session_timeout()

    if st.session_state['user']:
        user = st.session_state['user']
        if user.role == "Teacher":
            teacher_dashboard()
        elif user.role == "Parent":
            parent_dashboard()

if __name__ == "__main__":
    main()
