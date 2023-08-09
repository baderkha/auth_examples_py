from datetime import datetime,timedelta
from flask import Flask, request, jsonify,make_response
from user import User
from session import LoginSession
from app_setup import app, db

expiry_time_minutes = 10
session_cookie_name = 'ses_id'


@app.route('/')
def hello_world():
    return 'Hello, World!'

@app.route('/login',methods=['POST'])
def login_flow():
    try:
        # check if we have cookie
        # if cookie there 
        # check if we have session 
        # if session there check if it's not expired
        # if ok then do not login again 
        session_id_user_request  = request.cookies.get(session_cookie_name)
        if session_id_user_request :
            ses_db = db.session.query(LoginSession).filter_by(id=session_id_user_request).first()
            if ses_db and ses_db.expired_at > datetime.now():
                return jsonify({'message' : 'you are already logged in'}),200
            pass

        # Get JSON data from the request
        data = request.json
        email = data.get('email')
        password = data.get('password')

        user = db.session.query(User).filter_by(email=email).first()
        if user is None :
            return jsonify({'message' : 'user not found'}),401

        if user.password != password :
            return jsonify({'message' : 'Unauthorized'}),401

        # create a login session
        log_session = LoginSession(user_id = user.id,created_at = datetime.now(),expired_at = datetime.now()+timedelta(expiry_time_minutes))
        db.session.add(log_session)
        db.session.commit()

        response = make_response({'message': 'Logged In'})
        response.status_code = 200

        response.set_cookie(session_cookie_name, str(log_session.id), max_age=3600,httponly=True,samesite='Strict')
    
        return response
    except Exception as e:
        # Handle any errors
        error_message = str(e)
        return jsonify({'error': error_message}), 500
    pass

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        new_user = User(email='john_doe', password='john@example.com')
        db.session.add(new_user)
        db.session.commit()
    
    app.run(debug=True)