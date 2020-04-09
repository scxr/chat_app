from sqlalchemy import Column, Integer, String, ForeignKey, Date
from flask_appbuilder import Model

class chat_history(Model):
    id = Column('id', Integer, primary_key=True)
    msg = Column('msg', String(500))