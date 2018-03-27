import os
import sys
from sqlalchemy import Column, ForeignKey
from sqlalchemy import Integer, String
from sqlalchemy import DATETIME, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine


Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    email = Column(String(80), nullable=False)
    picture = Column(String(80))


class Category(Base):
    __tablename__ = 'category'

    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    categroy_item = relationship('Item', cascade='all, delete-orphan')

    @property
    def serialize(self):
        return {
               "name": self.name,
               "id": self.id,
               "user_id": self.user_id,
               }


class Item(Base):
    __tablename__ = 'category_item'

    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    date = Column(DateTime, default=func.now())
    #    date = Column(DATETIME, t)
    picture = Column(String(80))
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
            return {
                   "name": self.name,
                   "id": self.id,
                   "description": self.description,
                   "datecreated": self.date,
                   "category_id": self.category_id,
                   "user_id": self.user_id,
                   }

# insert at end of file

engine = create_engine('sqlite:///catalog.db')
Base.metadata.create_all(engine)
