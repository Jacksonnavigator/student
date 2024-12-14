from sqlalchemy import Column, String, Integer, create_engine, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, nullable=False, unique=True)
    email = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)
    role = Column(String, nullable=False)
    reset_token = Column(String, nullable=True)  # For password recovery

class Student(Base):
    __tablename__ = 'students'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)

class Result(Base):
    __tablename__ = 'results'
    id = Column(Integer, primary_key=True, autoincrement=True)
    student_id = Column(Integer, ForeignKey('students.id'), nullable=False)
    subject = Column(String, nullable=False)
    marks = Column(Integer, nullable=False)
    grade = Column(String, nullable=False)
    
    student = relationship("Student", back_populates="results")

# Relationship in the Student model
Student.results = relationship("Result", order_by=Result.id, back_populates="student")

# Database engine
engine = create_engine("sqlite:///database.db", echo=True)  # Replace with your DB URI
Base.metadata.create_all(engine)
