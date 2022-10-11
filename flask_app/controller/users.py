from flask_app import app
from flask import redirect, request, session, render_template, flash
from flask_app.models.user import User

@app.route('/login', methods=["POST"])
def login():
    
    if not User.validate_login(request.form):
        return redirect('/')    
    session['user_id'] = User.get_cur_user({"email" : request.form["email"]}).id 

    return redirect('/dashboard')

@app.route('/register', methods=["POST"])
def register():

    if not User.validate_registration(request.form):
        return redirect('/')
    data = {
        **request.form
    }
    User.save(data)
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    data = { "id" : session['user_id']}
    user = User.get_cur_user(data)
    return render_template("dashboard.html", user=user)

@app.route('/')
def index():
    return render_template("login.html")