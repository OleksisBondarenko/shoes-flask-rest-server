from cmath import log
from unicodedata import category
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY']='004f2af45d3a4e161a7dd2d17fdae46f'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///store.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Integer)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)

class Shoes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(50), unique=True, nullable=False)
    price = db.Column(db.Integer)

db.create_all()

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)
    return decorator


@app.route('/register', methods=['POST'])
def signup_user():  
    data = request.get_json()  
    hashed_password = generate_password_hash(data['password'], method='sha256')
 
    new_user = Users(public_id=str(uuid.uuid4()), name=data['username'], password=hashed_password, admin=False) 
    db.session.add(new_user)  
    db.session.commit()    

    return jsonify({'message': 'registeration successfully'})


@app.route('/login', methods=['POST'])  
def login_user(): 
    auth = request.authorization

    print(auth)   
    
    if not auth or not auth.username or not auth.password:  
        return make_response('could not verify', 401, {'Authentication': 'login required"'})    

    user = Users.query.filter_by(name=auth.username).first()   
     
    if check_password_hash(user.password, auth.password):

        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")
        return jsonify({'token' : token}) 

    return make_response('could not verify',  401, {'Authentication': '"login required"'})


@app.route('/users', methods=['GET'])
def get_all_users():  

    users = Users.query.all() 
    result = []   
    for user in users:   
        user_data = {}   
        user_data['public_id'] = user.public_id  
        user_data['name'] = user.name 
        user_data['password'] = user.password
        user_data['admin'] = user.admin 
       
        result.append(user_data)   

    return jsonify({'users': result})


@app.route('/buyed_shoes', methods=['POST'])
@token_required
def create_shoes(current_user):
    print(current_user)

    data = request.get_json() 

    new_shoes = Shoes(name=data['name'], category=data['category'], price=data['price'], user_id=current_user.id)  
    db.session.add(new_shoes)   
    db.session.commit()   

    return jsonify({'message' : 'new shoes created'})


@app.route('/buyed-shoes', methods=['GET'])
@token_required
def get_shoes(current_user):

    all_shoes = Shoes.query.filter_by(user_id=current_user.id).all()

    output = []
    for shoes in all_shoes:
        shoes_data = {}
        shoes_data['id'] = shoes.id
        shoes_data['name'] = shoes.name
        shoes_data['category'] = shoes.category
        shoes_data['price'] = shoes.price
        output.append(shoes_data)

    return jsonify({'data' : output})


@app.route('/shoes/<shoes_id>', methods=['DELETE'])
@token_required
def delete_shoes(current_user, shoes_id):  
    shoes = Shoes.query.filter_by(id=shoes_id, user_id=current_user.id).first()   
    if not shoes:   
        return jsonify({'message': 'shoes does not exist'})   

    db.session.delete(shoes)  
    db.session.commit()   

    return jsonify({'message': 'shoes deleted'})


if  __name__ == '__main__':  
     app.run(debug=True)