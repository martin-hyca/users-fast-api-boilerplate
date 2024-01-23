import bcrypt

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())


    print (bcrypt.hashpw("password".encode(), bcrypt.gensalt()).decode())



# add first user into the database: `sqlite3 database.sqlite` >
# INSERT INTO users (username, hashed_password) VALUES ('username', '$2b$12$1RCruufpMVoo2aynI2SSi.g.EMIvA3QC9CUM/sDS1sROouTgcRVFy');
