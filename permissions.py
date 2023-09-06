from sqlalchemy import  Column, Integer, String
from dataclasses import dataclass
from app_setup import db

@dataclass
# Define the model class
class Permission(db.Model):
    __tablename__ = 'permissions'

    permission_id:str = Column(String, primary_key=True)
    permission_description:str = Column(String)


