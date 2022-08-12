from re import search
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps
import os.path

basedir = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)

app.config['SECRET_KEY']='Th1s1ss3cr3t'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///' + os.path.join(basedir, 'store.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)

class Users(db.Model):
     id = db.Column(db.Integer, primary_key=True)
     public_id = db.Column(db.Integer)
     name = db.Column(db.String(50))
     password = db.Column(db.String(50))
     admin = db.Column(db.Boolean)

class products(db.Model):
     id = db.Column(db.Integer, primary_key=True)
     name = db.Column(db.String(50), unique=True, nullable=False)
     price = db.Column(db.Integer, nullable=False)

class products_edit(db.Model):
   id = db.Column(db.Integer, primary_key=True)
   name = db.Column(db.String(50), unique=True)
   price = db.Column(db.Integer)

def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):

      token = None

      if 'x-access-tokens' in request.headers:
         token = request.headers['x-access-tokens']

      if not token:
         return jsonify({'message': 'a valid token is missing'})

      try:
         data = jwt.decode(token, app.config['SECRET_KEY'])
         current_user = Users.query.filter_by(public_id=data['public_id']).first()
      except:
         return jsonify({'message': 'token is invalid'})
        

      return f(current_user, *args, **kwargs)
   return decorator

@app.route('/register', methods=['GET', 'POST'])
def signup_user():  
 data = request.get_json()  

 hashed_password = generate_password_hash(data['password'], method='sha256')
 
 new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False) 
 db.session.add(new_user)  
 db.session.commit()    

 return jsonify({'message': 'registered successfully'})

@app.route('/login', methods=['GET', 'POST'])  
def login_user(): 
 
  auth = request.authorization   

  if not auth or not auth.username or not auth.password:  
     return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})    

  user = Users.query.filter_by(name=auth.username).first()   
     
  if check_password_hash(user.password, auth.password):  
     token = jwt.encode({'public_id': user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])  
     return jsonify({'token' : token.decode('UTF-8')}) 

  return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})


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

@app.route('/product', methods=['POST', 'GET'])
@token_required
def create_product(current_user):
   
   data = request.get_json() 

   new_products = products(name=data['name'], price=data['price'], id=current_user.id)  
   db.session.add(new_products)   
   db.session.commit()   

   return jsonify({'message' : 'new product created'})

@app.route('/products/<product_id>', methods=['PUT'])
@token_required
def update_product(current_user, product_id):
   product = products.query.filter_by(id=product_id, user_id=current_user.id).first()
   if not product:
      return jsonify({'message':'product does not exist'})
   
   if products_edit.name not in None:
      update_name = products_edit.name
      product.name = update_name
      db.session.commit()
      return jsonify({'message':'Name of an item has been updated'})

   if products_edit.price not in None:
      update_price = products_edit.price
      product.price = update_price
      db.session.commit()
      return jsonify({'message':'Price of an item has been updated'})



@app.route('/products/<product_id>', methods=['DELETE'])
@token_required
def delete_product(current_user, product_id):  
    product = products.query.filter_by(id=product_id, user_id=current_user.id).first()   
    if not product:   
       return jsonify({'message': 'product does not exist'})
    else:
      db.session.delete(product)  
      db.session.commit()   
      return jsonify({'message': 'product deleted'})   

    

@app.before_first_request
def create_tables():
    db.create_all()

if  __name__ == '__main__':  
     app.run(debug=True)
