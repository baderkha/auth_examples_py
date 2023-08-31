from datetime import datetime,timedelta
from flask import Flask, request, jsonify,make_response,session
from user import User
from session import LoginSession
from app_setup import app, db
import jwt

expiry_time_minutes = 10
session_cookie_name = 'ses_id'
jwt_cookie_name = "jwt_cookie"
issuer = "rakan-secret-incorportated.com"
token_secret = "someone_cool_123"

@app.route('/')
def hello_world():
    return 'Hello, World!'

    # status codes to remember
    # success
    # 200 -> ok (get update delete)
    # 201 -> created (create post)
    # 202 -> your request has been accepeted and you need to use another route to poll for status


    # informational status
    # 301 -> redirecting user

    # failure (by client) (nothing wrong with your code something wrong with theirs)
    # 400 -> users request is missing some stuff or is invalid
    # 401 -> unauthorized access
    # 404 -> not found (they made a request to a resource that does not exist)
    # 403 -> forebidden (they are authroized in the system but they;re accessing a resource that is not theirs)
    # 419 -> rate limit (you hit the route too many times and you should cool down)
    # 418 -> i'm a teapot


    # failure (by server)

    # 500 -> server failed for generic reason
    # 501 -> not implemented



def jwt_login_verify(view_function):
    def wrapper (*args,**kwargs):
        jwt_token = ""
        
        # grabbing token from either cookie or Authorization header
        jwt_token_cookie  = request.cookies.get(jwt_cookie_name)
        jwt_token_header = request.headers.get("Authorization",default="")
        if jwt_token_cookie is not None and jwt_token_cookie != '':
            jwt_token = jwt_token_cookie
        elif jwt_token_header != '' :
            jwt_token = jwt_token_header
        else :
            return jsonify({'message' : 'you are not logged in'}),401
        jwt_token = jwt_token.replace("Bearer ","")

        # parse the token
        payload = jwt.decode(jwt_token, token_secret, algorithms=["HS256"])
        if payload is None:
            return jsonify({'message' : 'you are not logged in'}),401
        
        # is the exp passed the duration
        expiryTimeSeconds = payload["exp"]
        hasExpired = expiryTimeSeconds <= int(datetime.now().timestamp()) 
        issuerFromToken = payload["iss"]
        amiTheIssuer = issuer == issuerFromToken

        if hasExpired or not amiTheIssuer :
            return jsonify({'message' : 'you are not logged in'}),401
        
        session["jwt_payload"] = payload
        return view_function(*args,**kwargs)
    wrapper.__name__ = view_function.__name__
    return wrapper



def session_login_middleware(view_function):
    def wrapper(*args, **kwargs):
        session_id_user_request  = request.cookies.get(session_cookie_name)
        if session_id_user_request is not None and session_id_user_request != '':
            ses_db = db.session.query(LoginSession).filter_by(id=session_id_user_request).first()
            if ses_db and ses_db.expired_at < datetime.now():
                return jsonify({'message' : 'your session is expired'}),401
            elif ses_db is None:
                return jsonify({'message' : 'you are not logged in'}),401
        else :
            return jsonify({'message' : 'you are not logged in'}),401
        return view_function(*args, **kwargs)
    wrapper.__name__ = view_function.__name__
    return wrapper

def session_extension_middleware(view_function):
    def wrapper(*args,**kwargs):
        session_id_user_request  = request.cookies.get(session_cookie_name)
        if session_id_user_request is not None and session_id_user_request != '':
            ses_db = db.session.query(LoginSession).filter_by(id=session_id_user_request).first()
            ses_db.expired_at = datetime.now()+timedelta(minutes=expiry_time_minutes)
            db.session.commit()
            response = make_response()
            # Set a new cookie
            response.set_cookie(session_cookie_name, str(ses_db.id), max_age=3600,httponly=True,samesite='Strict')
            return response
        return view_function(*args,**kwargs)
    wrapper.__name__ = view_function.__name__
    return wrapper



@app.route('/dogsv2',methods=['GET'])
@jwt_login_verify
def get_dogs_v2(): 
    return {
        "dog" : "woof"
    }

@app.route('/jwt_extend',methods=['POST'])
@jwt_login_verify
def extend_jwt():
    expiryTime =  datetime.now()+timedelta(minutes=expiry_time_minutes)
    expiryTime = int(expiryTime.timestamp())
    json_token = jwt.encode({
        "exp": expiryTime, # expiry time
        "iat": int(datetime.now().timestamp()), # issued at time
        "iss": issuer, #issuer
        "sub": session["jwt_payload"]["sub"] # user_id / email
    },key=token_secret,algorithm="HS256")

    response = make_response({'message': 'Logged In','token':json_token})
    response.status_code = 200
    response.set_cookie(jwt_cookie_name, json_token, max_age=3600,httponly=True,samesite='Strict')
    return response
    

@app.route('/dogs',methods=['GET'])
@session_login_middleware
@session_extension_middleware
def get_dogs(): 
    return {
        "dog" : "woof"
    }

@app.route('/cats',methods=['GET'])
@session_login_middleware
def get_cats():
    return {
        "cat" : "meow"
    }


@app.route('/logout',methods=['POST'])
def logout():
    session_id_user_request  = request.cookies.get(session_cookie_name)
    if session_id_user_request is not None and session_id_user_request != '':
        ses_db = db.session.query(LoginSession).filter_by(id=session_id_user_request).first()
        ses_db.expired_at = datetime.now() + timedelta(minutes=-1)
        db.session.commit()
    response = make_response({"message":"logged out !"})
    response.delete_cookie(session_cookie_name)
    return response

@app.route('/login_jwt',methods=['POST'])   
def login_jwt():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = db.session.query(User).filter_by(email=email).first()
    if user is None :
        return jsonify({'message' : 'user not found'}),401

    if user.password != password :
        return jsonify({'message' : 'Unauthorized'}),401
    expiryTime =  datetime.now()+timedelta(minutes=expiry_time_minutes)
    expiryTime = int(expiryTime.timestamp())
    json_token = jwt.encode({
        "exp": expiryTime, # expiry time
        "iat": int(datetime.now().timestamp()), # issued at time
        "iss": issuer, #issuer
        "sub": email # user_id / email
    },key=token_secret,algorithm="HS256")

    response = make_response({'message': 'Logged In','token':json_token})
    response.status_code = 200
    response.set_cookie(jwt_cookie_name, json_token, max_age=3600,httponly=True,samesite='Strict')
    return response


    

@app.route('/login',methods=['POST'])
def login_flow_session():
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
        log_session = LoginSession(user_id = user.id,created_at = datetime.now(),expired_at = datetime.now()+timedelta(minutes=expiry_time_minutes))
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
    app.secret_key = 'super secret key'
    app.config['SESSION_TYPE'] = 'filesystem'
    
    app.run(debug=True)