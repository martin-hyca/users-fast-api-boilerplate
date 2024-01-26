from sqlalchemy import Column, Integer, String, Table, ForeignKey
from sqlalchemy.orm import relationship
from mydatabase import Base

# Association table for many-to-many relationship
user_roles_table = Table('user_roles', Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id')),
    Column('role_id', Integer, ForeignKey('roles.id'))
)


class Role(Base):
    __tablename__ = 'roles'

    id = Column(Integer, primary_key=True, autoincrement=True)
    role_name = Column(String, unique=True)

    def __repr__(self):
        return f"<Role(role_name='{self.role_name}')>"
    



class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

    # Many-to-many relationship with Role
    roles = relationship("Role", secondary=user_roles_table, backref="users")


    def __repr__(self):
        return f"<User(username='{self.username}')>"