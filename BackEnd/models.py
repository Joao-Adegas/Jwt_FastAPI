from sqlalchemy import Column, Integer , String
from database import Base,engine

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer(),primary_key=True,index=True)

    username = Column(String(256),unique=True,index=True)

    hashed_password = Column(String(256))

User.metadata.create_all(bind=engine)

