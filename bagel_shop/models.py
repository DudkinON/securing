from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context

Base = declarative_base()


# ADD YOUR USER MODEL HERE

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    password_hash = Column(String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)


class Bagel(Base):
    __tablename__ = 'bagel'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    picture = Column(String)
    description = Column(String)
    price = Column(String)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'picture': self.picture,
            'description': self.description,
            'price': self.price
        }


engine = create_engine('sqlite:///bagelShop.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
Base.metadata.create_all(engine)


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


def get_user_by_id(id):
    return session.query(User).filter_by(id=id).first()


def get_bagels():
    return session.query(Bagel).all()


def create_bagel(name, description, picture, price):
    new_bagel = Bagel(name=name, description=description, picture=picture,
                      price=price)
    session.add(new_bagel)
    session.commit()
    return new_bagel
