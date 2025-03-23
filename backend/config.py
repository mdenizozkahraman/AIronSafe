import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'mysecretkey')
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:pl35Ryt!@aironsafe-db:5432/aironsafe'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
