from sqlalchemy import  Column, Integer, String

from app_setup import db

# Define the model class
class User(db.Model):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String)
    password = Column(String)


