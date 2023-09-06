from sqlalchemy import  Column, Integer, String

from app_setup import db

# Define the model class
class Roles(db.Model):
    __tablename__ = 'roles'
    role_id = Column(String, primary_key=True)
    role_description = Column(String)


