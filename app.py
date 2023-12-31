from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
import json
from bson import json_util, ObjectId
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from bson.regex import Regex
from mongoengine import Document, StringField, URLField, IntField
from mongoengine.fields import EmailField
from mongoengine import connect
from flask_cors import CORS

app = Flask(__name__)

app.config['SECRET_KEY'] = 'supersecretkey'
app.config['JWT_SECRET_KEY'] = 'supersecretkey'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600  # Access token expires in 1 hour
app.config["MONGO_URI"] = "mongodb://localhost:27017/my_BOOKSTORE"
db = PyMongo(app).db
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)

connect(db='my_BOOKSTORE', host='mongodb://localhost:27017/my_BOOKSTORE')


class User(Document):
    name = StringField(required=True)
    email = EmailField(required=True, unique=True)
    password = StringField(required=True)


class Cart(Document):
    user_id = StringField(required=True)
    book_id = StringField(required=True)
    quantity = StringField(required=True)


class Order(Document):
    author = StringField(required=True)
    book_ref = StringField(required=True)
    customers_rating = IntField(required=True)
    description = StringField(required=True)
    discount = StringField(required=True)
    images = StringField(required=True)
    price = IntField(required=True)
    quantity = IntField(required=True)
    title = StringField(required=True)


@app.route('/book/signup', methods=["POST"])
def signup():
    data = request.get_json()
    email = data['email']
    password = data['password']
    name = data['name']

    if email == False or password == False or name == False:
        return jsonify({"message": "All Credentials are required"}), 400

    existing_user = db.user.find_one({'email': email})
    if existing_user:
        return jsonify({"message": "USER IS ALREADY REGISTERED"}), 400

    bcrypt_pass = bcrypt.generate_password_hash(password, rounds=5).decode("UTF-8")
    new_user = User(name=name, email=email, password=bcrypt_pass)
    new_user.save()
    return jsonify({'message': 'Registration Successful'})


@app.route('/book/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']
    user = db.user.find_one({'email': email})
    if user and bcrypt.check_password_hash(user['password'], password):
        access_token = create_access_token(identity=email)
        return jsonify({'access_token': access_token, "name": user['name']})

    return jsonify({'message': 'Invalid credentials'})


@app.route('/book', methods=['GET'])
def books():
    data = db.books.find()
    return json.loads(json_util.dumps(data))


@app.route('/book/filter', methods=['GET'])
def filter_books():
    query = request.args.get('query')
    field = request.args.get('field')
    search_filter = {}
    if query and field:
        if field == 'title':
            search_filter['title'] = {'$regex': query, '$options': 'i'}
        elif field == 'author':
            search_filter['author'] = {'$regex': query, '$options': 'i'}
        elif field == 'customers_rating':
            try:
                rating = float(query)
                search_filter['customers_rating'] = rating
            except ValueError:
                return jsonify({'message': 'Invalid rating'}), 400
    elif query and not field:
        books = db.books.find({'$or': [
            {'title': {'$regex': query, '$options': 'i'}},
            {'author': {'$regex': query, '$options': 'i'}},
            {'description': {'$regex': query, '$options': 'i'}},
            {'discount': {'$regex': query, '$options': 'i'}},
            {'images': {'$regex': query, '$options': 'i'}},
            {'price': int(query) if query.isdigit() else query},
            {'title': {'$regex': query, '$options': 'i'}}
        ]})
        return json.loads(json_util.dumps(books))

    books = db.books.find(search_filter)
    return json.loads(json_util.dumps(books))


@app.route('/cart', methods=['POST'])
def get_cart():
    data = request.get_json()
    result = db.cart.insert_one(data)
    inserted_id = str(result.inserted_id)
    return jsonify({"message": inserted_id})


@app.route('/cart/<cart_item_id>', methods=['DELETE'])
def remove_from_cart(cart_item_id):
    result = db.cart.delete_one({'_id': ObjectId(cart_item_id)})

    if result.deleted_count == 0:
        return jsonify({'message': 'Cart item not found'})

    return jsonify({'message': 'Cart item deleted successfully'})


@app.route('/orders', methods=['POST'])
def create_order():
    cart_items = request.get_json()
    
    if not cart_items:
        return jsonify({'message': 'No cart items found'})
    
    order_docs = []
    for cart_item in cart_items:
        order_data = {
            "author": cart_item.get("author"),
            "book_ref": cart_item.get("box-book href"),
            "customers_rating": cart_item.get("customers_rating"),
            "description": cart_item.get("description"),
            "discount": cart_item.get("discount"),
            "images": cart_item.get("images"),
            "price": cart_item.get("price"),
            "quantity": cart_item.get("quantity"),
            "title": cart_item.get("title")
        }
        order_doc = Order(**order_data)
        order_docs.append(order_doc)

    if order_docs:
        Order.objects.insert(order_docs)

    return jsonify({"message": "Orders created successfully"})

@app.route('/orders/<order_id>', methods=['DELETE'])
def delete_order(order_id):
    result = db.orders.delete_one({"_id": ObjectId(order_id)})

    if result.deleted_count == 0:
        return jsonify({'message': 'Ordered item not found'})

    return jsonify({'message': 'Ordered item deleted successfully'})


if __name__ == '__main__':
    app.run(debug=True)