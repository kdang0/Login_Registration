from flask_app.config.mysqlconnection import connectToMySQL
from flask import session, flash
import re
from flask_app import bcrypt
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 
class User:
    def __init__(self, data):
        self.id = data["id"]
        self.first_name = data["first_name"]
        self.last_name = data["last_name"]
        self.email = data["email"]
        self.password = data["password"]


    @classmethod
    def get_cur_user(cls, data):
        query = "SELECT * FROM users WHERE"
        query += ' AND'.join(f' {key} = %({key})s' for key in data)
        query += ";"
        user = connectToMySQL('users_login').query_db(query, data)
        if user:
            return cls(user[0])
    @classmethod
    def save(cls, data):
        data['password'] = bcrypt.generate_password_hash(data["password"])
        query = "INSERT INTO users (first_name, email, last_name, password)"
        query += " VALUES(%(first_name)s, %(email)s, %(last_name)s, %(password)s)"

        return connectToMySQL('users_login').query_db(query,data)


    @staticmethod
    def validate_registration(user):
        is_valid = True
        if len(user["first_name"]) < 2 and not user["first_name"].isalpha():
            flash("Invalid firstname")
            is_valid = False
        if len(user["last_name"]) < 2 and not user["last_name"].isalpha():
            flash("Invalid lastname")
            is_valid = False
        if not EMAIL_REGEX.match(user["email"]):
            flash("Invalid email address")
            is_valid = False

        results = User.get_cur_user({"email" : user["email"]})
        if results:
            flash("This email is already taken")
            is_valid = False
        if len(user['password']) < 8:
            flash("Invalid password")
            is_valid = False
        if user['password'] != user['confirm_password']:
            flash("Password's don't match")
            is_valid = False

        return is_valid
    
    @staticmethod
    def validate_login(data):
        
        user_in_db = User.get_cur_user({"email" : data["email"]})
        if not user_in_db:
            flash("Invalid Email/Password")
            return False
        if not bcrypt.check_password_hash(user_in_db.password, data['password']):
            flash("Invalid Email/Password")
            return False
        return True