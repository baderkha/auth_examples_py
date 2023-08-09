from sqlalchemy import  Column, Integer, String, DateTime

from app_setup import db

# Define the model class
class LoginSession(db.Model):
    __tablename__ = 'login_sessions'
    id = Column(Integer, primary_key=True,autoincrement=True)
    user_id = Column(Integer,index=True)
    created_at = Column(DateTime)
    expired_at = Column(DateTime) ## if session is expired then no login


