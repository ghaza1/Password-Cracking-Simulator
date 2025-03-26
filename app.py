import os
import datetime
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy ;from sqlalchemy.exc import IntegrityError
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_jwt
from flask_bcrypt import Bcrypt
import functools
from datetime import timedelta,timezone
from dotenv import load_dotenv

load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'ahmed')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'mysql://root:@localhost/infosec')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'ahmed@1234')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=10)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_IDENTITY_CLAIM'] = 'sub'

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# JWT Token blocklist
class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now(timezone.utc))

# Check if token is in blocklist
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = db.session.query(TokenBlocklist).filter_by(jti=jti).first()
    return token is not None

# Models
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, onupdate=datetime.datetime.now(timezone.utc))
    
    def __init__(self, name, username, password):
        self.name = name
        self.username = username
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'username': self.username,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Product(db.Model):
    __tablename__ = 'products'
    
    pid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    pname = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, onupdate=datetime.datetime.now(timezone.utc))
    
    def to_dict(self):
        return {
            'pid': self.pid,
            'pname': self.pname,
            'description': self.description,
            'price': self.price,
            'stock': self.stock,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

# Create tables
with app.app_context():
    db.create_all()

# Authentication helper functions
def login_user():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'status': 'error', 'message': 'Missing username or password'}), 400
    
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    
    if not user or not user.check_password(password):
        return jsonify({'status': 'error', 'message': 'Invalid username or password'}), 401
    
    # Generate JWT token valid for 10 minutes
    access_token = create_access_token(
        identity=user.id,
        additional_claims={"username": user.username}
    )
    
    return jsonify({
            'token': access_token,
        }
    ), 200

def signup_user():
    data = request.get_json()
    
    if not data:
        return jsonify({'status': 'error', 'message': 'No input data provided'}), 400
    
    # Validate required fields
    for field in ['name', 'username', 'password']:
        if field not in data:
            return jsonify({'status': 'error', 'message': f'Missing {field}'}), 400
    
    try:
        # Create new user
        new_user = User(
            name=data['name'],
            username=data['username'],
            password=data['password']
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            'status': 'success', 
            'message': 'User created successfully', 
            'data': {'user': new_user.to_dict()}
        }), 201
    
    except IntegrityError:
        db.session.rollback()
        return jsonify({
            'status': 'error', 
            'message': 'Username already exists'
        }), 409
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error', 
            'message': f'An error occurred: {str(e)}'
        }), 500

# Custom decorator for checking user permissions
def user_required(f):
    @functools.wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user_id = kwargs.get('id')
        
        # Convert to int for comparison
        if int(user_id) != int(current_user_id):
            return jsonify({
                'status': 'error', 
                'message': 'Unauthorized access'
            }), 403
        
        return f(*args, **kwargs)
    
    return decorated_function

# Routes
# Authentication routes
@app.route('/signup', methods=['POST'])
def signup():
    return signup_user()

@app.route('/login', methods=['POST'])
def login():
    return login_user()

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    now = datetime.datetime.now(timezone.utc)
    
    # Add token to blocklist
    db.session.add(TokenBlocklist(jti=jti, created_at=now))
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': 'Successfully logged out'
    }), 200

# User operations
@app.route('/users/<int:id>', methods=['PUT'])
@user_required
def update_user(id):
    user = User.query.get_or_404(id)
    data = request.get_json()
    
    if not data:
        return jsonify({
            'status': 'error',
            'message': 'No input data provided'
        }), 400
    
    try:
        # Update user details
        if 'name' in data:
            user.name = data['name']
        if 'password' in data:
            user.password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'User updated successfully',
            'data': {'user': user.to_dict()}
        }), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'An error occurred: {str(e)}'
        }), 500

# Product operations
@app.route('/products', methods=['POST'])
@jwt_required()
def add_product():
    data = request.get_json()
    
    if not data:
        return jsonify({
            'status': 'error',
            'message': 'No input data provided'
        }), 400
    
    # Validate required fields
    for field in ['pname', 'price', 'stock']:
        if field not in data:
            return jsonify({
                'status': 'error',
                'message': f'Missing {field}'
            }), 400
    
    try:
        # Create new product
        new_product = Product(
            pname=data['pname'],
            description=data.get('description', ''),
            price=float(data['price']),
            stock=int(data['stock'])
        )
        
        db.session.add(new_product)
        db.session.commit()
        
        return jsonify({
           'message': 'Product created successfully',
        }), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'An error occurred: {str(e)}'
        }), 500

@app.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    try:
        # Add pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        pagination = Product.query.paginate(page=page, per_page=per_page)
        products = pagination.items
        
        return jsonify({
        
                'products': [product.to_dict() for product in products],
                'pagination': {
                    'total': pagination.total,
                    'pages': pagination.pages,
                    'page': page,
                    'per_page': per_page,
                    'next': pagination.next_num,
                    'prev': pagination.prev_num
                }
            }
        ), 200
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'An error occurred: {str(e)}'
        }), 500

@app.route('/products/<int:pid>', methods=['GET'])
@jwt_required()
def get_product(pid):
    try:
        product = Product.query.get_or_404(pid)
        
        return jsonify({
            'product': product.to_dict()
        }), 200
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'An error occurred: {str(e)}'
        }), 500

@app.route('/products/<int:pid>', methods=['PUT'])
@jwt_required()
def update_product(pid):
    product = Product.query.get_or_404(pid)
    data = request.get_json()
    
    if not data:
        return jsonify({
            'status': 'error',
            'message': 'No input data provided'
        }), 400
    
    try:
        # Update product details
        if 'pname' in data:
            product.pname = data['pname']
        if 'description' in data:
            product.description = data['description']
        if 'price' in data:
            product.price = float(data['price'])
        if 'stock' in data:
            product.stock = int(data['stock'])
        
        db.session.commit()
        
        return jsonify({
            'message': 'Product updated successfully',
            'product': product.to_dict()
        }), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'An error occurred: {str(e)}'
        }), 500

@app.route('/products/<int:pid>', methods=['DELETE'])
@jwt_required()
def delete_product(pid):
    try:
        product = Product.query.get_or_404(pid)
        
        db.session.delete(product)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Product deleted successfully'
        }), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'An error occurred: {str(e)}'
        }), 500

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({
        'status': 'error',
        'message': 'Resource not found'
    }), 404

@app.errorhandler(500)
def internal_server_error(e):
    return jsonify({
        'status': 'error',
        'message': 'Internal server error'
    }), 500

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'status': 'error',
        'message': 'The token has expired',
        'error': 'token_expired'
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'status': 'error',
        'message': 'Signature verification failed',
        'error': 'invalid_token'
    }), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        'status': 'error',
        'message': 'Request does not contain an access token',
        'error': 'authorization_required'
    }), 401

# Run the application
if __name__ == '__main__':
    app.run(debug="TRUE",host='127.0.0.1', port=5000)