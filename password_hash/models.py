from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    password_hash = Column(String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)


engine = create_engine('sqlite:///users.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


def user_exist(username):
    if session.query(User).filter_by(username=username).first() is not None:
        return True
    else:
        return False


def create_user(username, password):
    user = User(username=username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return user


def get_user(username):
    return session.query(User).filter_by(username=username).first()


Base.metadata.create_all(engine)
