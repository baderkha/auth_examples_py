from sqlalchemy import  Column, Integer, String

from app_setup import db

# Define the model class
class RolePermissions(db.Model):
    __tablename__ = 'role_permissions'
    id = Column(Integer, primary_key=True)
    permission_id = Column(String)
    role_id = Column(String)


