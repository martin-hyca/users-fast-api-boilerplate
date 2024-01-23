from sqlalchemy import Column, Integer, String
from mydatabase import Base

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

    def __repr__(self):
        return f"<User(username='{self.username}')>"