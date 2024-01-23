from mydatabase import engine, Base
from models import User  # Import the User model

def initialize_database():
    Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    initialize_database()