from sqlalchemy import create_engine, Column,Integer,String,TEXT
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker 

SQLALCHEMY_DATABASE_URL = "sqlite:///./teste.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,connect_args={'check_same_thread':False}
)

SessionLocal = sessionmaker(autocommit = False, autoflush = False, bind = engine)

Base = declarative_base()