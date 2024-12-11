from sqlalchemy import Column, Integer, String, ForeignKey, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

# Initialize the base for the models
Base = declarative_base()

# User model
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, nullable=False)  # Either 'Teacher' or 'Parent'

# Student model
class Student(Base):
    __tablename__ = "students"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)

# Result model
class Result(Base):
    __tablename__ = "results"
    id = Column(Integer, primary_key=True, autoincrement=True)
    student_id = Column(Integer, ForeignKey("students.id"), nullable=False)
    subject = Column(String, nullable=False)
    marks = Column(Integer, nullable=False)
    grade = Column(String, nullable=False)

    # Relationship to fetch the associated student
    student = relationship("Student", back_populates="results")

# Define the back_populates in Student
Student.results = relationship("Result", order_by=Result.id, back_populates="student")

# Database connection
DATABASE_URL = "sqlite:///results_management.db"  # Update this to your preferred database URL
engine = create_engine(DATABASE_URL)

# Create all tables
Base.metadata.create_all(engine)
