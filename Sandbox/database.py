from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, select, Text, NullPool
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

Base = declarative_base()
metadata = MetaData()

class Database:
    def __init__(self, db_url='sqlite:///db/sandbox.db'):
        self.engine = create_engine(db_url, echo = False, poolclass=NullPool)
        self.Session = sessionmaker(bind=self.engine)
        metadata.reflect(bind=self.engine)
        self._initialize()
        self.startup()

    def _initialize(self):
        metadata.create_all(self.engine)

    def create_table(self, table_name, columns):
        if table_name in metadata.tables:
            raise ValueError(f"Table {table_name} already exists.")
        
        Table(
                table_name, metadata, 
                *columns
        )
        metadata.create_all(self.engine)

    def insert(self, table_name, loaded_values):
        if table_name not in metadata.tables:
            raise ValueError(f"Table {table_name} does not exist.")
        
        table = metadata.tables[table_name]
        ins = table.insert().values(**loaded_values)
        conn = self.engine.connect()
        result = conn.execute(ins)
        conn.commit()

    def get_row(self, table_name, id_value):
        if table_name not in metadata.tables:
            raise ValueError(f"Table {table_name} does not exist.")
        
        table = metadata.tables[table_name]
        ins = table.select().where(table.c.id==id_value)
        conn = self.engine.connect()
        try: 
            return conn.execute(ins).first()
        except:
            return None
    
    def get_value(self, table_name, id_value, wanted_value):
        if table_name not in metadata.tables:
            raise ValueError(f"Table {table_name} does not exist.")
        
        table = metadata.tables[table_name]
        ins = select(table.c[wanted_value]).where(table.c.id==id_value)
        conn = self.engine.connect()
        try:
            return conn.execute(ins).first()[0]
        except:
            return None
    
    def get_id(self, table_name, wanted_key, wanted_value):
        if table_name not in metadata.tables:
            raise ValueError(f"Table {table_name} does not exist.")
        
        table = metadata.tables[table_name]
        ins = select(table.c['id']).where(table.c[wanted_key]==wanted_value)
        conn = self.engine.connect()
        try:
            return conn.execute(ins).first()[0]
        except:
            return None

    def delete_row(self, table_name, id_value):
        if table_name not in metadata.tables:
            raise ValueError(f"Table {table_name} does not exist.")
        
        table = metadata.tables[table_name]
        ins = table.delete().where(table.c.id==id_value)
        conn = self.engine.connect()
        conn.execute(ins)
        conn.commit()

    def get_table(self, table_name):
        if table_name not in metadata.tables:
            raise ValueError(f"Table {table_name} does not exist.")
        
        table = metadata.tables[table_name]
        ins = table.select()
        conn = self.engine.connect()
        try: 
            return conn.execute(ins)
        except:
            return None
    
    def startup(self):
        tables = {
            'configuration': [
                Column('id', Integer, primary_key=True),
                Column('vm_label', String),
                Column('snapshot', String),
                Column('vm_default_path', String),
                Column('vboxmanage_path', String),
                Column('virustotal_api_key', String)
            ],
            'submit': [
                Column('id', Integer, primary_key=True),
                Column('file_path', String),
                Column('vm_label', String),
                Column('modules', Text),
                Column('post_modules', Text),
                Column('status', String),
                Column('submission_time', String),
                Column('file_name', String)
            ],
            'running': [
                Column('id', Integer, primary_key=True),
                Column('file_path', String),
                Column('vm_label', String),
                Column('modules', Text),
                Column('post_modules', Text),
                Column('status', String),
                Column('submission_time', String),
                Column('file_name', String)
            ],
            'report': [
                Column('id', Integer, primary_key=True),
                Column('file_path', String),
                Column('vm_label', String),
                Column('modules', Text),
                Column('post_modules', Text),
                Column('status', String),
                Column('submission_time', String),
                Column('file_name', String)
            ]
        }
        
        for table_name, columns in tables.items():
            if table_name not in metadata.tables:
                self.create_table(table_name, columns)
            