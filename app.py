from flask import Flask, jsonify, request, g
import bcrypt
import mysql.connector
import jwt
from dotenv import load_dotenv
import datetime
from functools import wraps
import uuid
import json
import stripe
import os

stripe.api_key = os.getenv("STRIPE_API_KEY")
load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("FLASK_SECRET_KEY")
app.config['SECRET_KEY'] = app.secret_key

def get_db():
    if 'db' not in g:
        g.db = mysql.connector.connect(
            host=os.getenv('DB_HOST'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME')
        )
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.teardown_appcontext
def teardown_db(e=None):
    close_db()

def generate_jwt(email):
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=160)
    payload = {'email': email, 'exp': expiration_time}
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")
    return token

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({"message": "Token is missing!"}), 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            email = data['email']
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token!"}), 401

        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT id, name, email, cart_id, role FROM user WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"message": "User not found"}), 404

        return f(user, *args, **kwargs)

    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(user, *args, **kwargs):
        if user.get("role") != "admin":
            return jsonify({"message": "Admin access required"}), 403
        return f(user, *args, **kwargs)
    return decorated_function


@app.route("/")
@token_required
@admin_required
def home(user):
    return "Hello!"



@app.route("/signup", methods=['POST', 'OPTIONS'])
def submit_creds():
    if request.method == 'OPTIONS':
        return '', 204

    data = request.json
    name = data.get("name")
    email = data.get("email")
    pswd = data.get("password")

    salt = bcrypt.gensalt()
    hashed_pswd = bcrypt.hashpw(pswd.encode("utf-8"), salt)

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM user WHERE email = %s", (email,))
    if cursor.fetchone():
        return jsonify({"msg": "User already exists!"}), 400

    cursor.execute(
        "INSERT INTO user (name, email, password) VALUES (%s, %s, %s)",
        (name, email, hashed_pswd)
    )
    db.commit()

    return jsonify({
        "msg": f"Hello {name}, Creds Successfully Received!",
        "pswd": pswd,
        "name": name,
        "email": email,
    }), 201

@app.route("/login", methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return '', 204

    data = request.json
    email = data.get("email")
    pswd = data.get("password")

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT email, password, name FROM user WHERE email=%s", (email,))
    user_ex = cursor.fetchone()

    if user_ex:
        stored_email, stored_password, name = user_ex
        if bcrypt.checkpw(pswd.encode("utf-8"), stored_password.encode("utf-8")):
            token = generate_jwt(stored_email)
            return jsonify({
                "message": "Logged in!",
                "token": token,
                "email": email,
                "user": name,
            })
        else:
            return jsonify({"message": "Invalid password"}), 401

    return jsonify({"msg": "User doesn't exist!"}), 404

@app.route('/products', methods=['GET'])
def get_products():
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM products")
        products = cursor.fetchall()

        for product in products:
            if 'images' in product and isinstance(product['images'], str):
                try:
                    product['images'] = json.loads(product['images'])
                except json.JSONDecodeError:
                    product['images'] = []

        return jsonify(products), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
        product = cursor.fetchone()

        if product:
            if 'images' in product and isinstance(product['images'], str):
                try:
                    product['images'] = json.loads(product['images'])
                except json.JSONDecodeError:
                    product['images'] = []
            return jsonify(product), 200
        else:
            return jsonify({"error": "Product not found"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/products', methods=['POST'])
@token_required
@admin_required
def add_product():
    try:
        data = request.json

        db = get_db()
        cursor = db.cursor()

        cursor.execute("""
            INSERT INTO products (name, description, price, stock, category, images)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            data.get('name'),
            data.get('description'),
            data.get('price'),
            data.get('stock'),
            data.get('category'),
            json.dumps(data.get('images', []))
        ))

        db.commit()
        return jsonify({"message": "Product added successfully!"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/products/<int:product_id>', methods=['PUT'])
@token_required
@admin_required
def update_product(product_id):
    try:
        updated_product = request.json

        fields = []
        values = []

        allowed_fields = ['name', 'description', 'price', 'stock', 'category', 'images']
        for key in updated_product:
            if key in allowed_fields:
                if key == 'images':
                    fields.append(f"{key} = %s")
                    values.append(json.dumps(updated_product[key]))
                else:
                    fields.append(f"{key} = %s")
                    values.append(updated_product[key])

        if not fields:
            return jsonify({"error": "No valid fields to update"}), 400

        values.append(product_id)

        db = get_db()
        cursor = db.cursor()
        sql = f"UPDATE products SET {', '.join(fields)} WHERE id = %s"
        cursor.execute(sql, tuple(values))
        db.commit()

        if cursor.rowcount == 0:
            return jsonify({"error": "Product not found"}), 404

        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
        product = cursor.fetchone()
        if product and 'images' in product and isinstance(product['images'], str):
            try:
                product['images'] = json.loads(product['images'])
            except json.JSONDecodeError:
                product['images'] = []

        return jsonify(product), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/products/<int:product_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_product(product_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM products WHERE id = %s", (product_id,))
        db.commit()

        if cursor.rowcount == 0:
            return jsonify({"error": "Product not found"}), 404

        return jsonify({"message": "Product deleted"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/cart/add", methods=["POST"])
@token_required
def add_to_user_cart(user):
    try:
        data = request.json
        product_id = data.get("id")
        qty = data.get("qty", 1)

        if not product_id or qty <= 0:
            return jsonify({"error": "Invalid product ID or quantity"}), 400

        db = get_db()
        cursor = db.cursor()

        # Check if user already has a cart
        cart_id = user.get("cart_id")  # ✅ FIXED: use snake_case
        if not cart_id:
            # Create new cart
            cart_id = str(uuid.uuid4())
            cursor.execute("INSERT INTO carts (cart_id) VALUES (%s)", (cart_id,))
            cursor.execute("UPDATE user SET cart_id = %s WHERE id = %s", (cart_id, user["id"]))  # ✅ FIXED
            db.commit()

        # Check if product already in cart
        cursor.execute("""
            SELECT qty FROM cart_items
            WHERE cart_id = %s AND product_id = %s
        """, (cart_id, product_id))
        existing = cursor.fetchone()

        if existing:
            # Update qty
            new_qty = existing[0] + qty
            cursor.execute("""
                UPDATE cart_items SET qty = %s
                WHERE cart_id = %s AND product_id = %s
            """, (new_qty, cart_id, product_id))
        else:
            # Add new item
            cursor.execute("""
                INSERT INTO cart_items (cart_id, product_id, qty)
                VALUES (%s, %s, %s)
            """, (cart_id, product_id, qty))

        db.commit()

        # Return updated cart
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT product_id AS id, qty
            FROM cart_items
            WHERE cart_id = %s
        """, (cart_id,))
        items = cursor.fetchall()

        return jsonify({
            "cart_id": cart_id,
            "products": items
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/cart", methods=["GET"])
@token_required
def get_cart():
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT c.cart_id, ci.product_id AS id, ci.qty
            FROM carts c
            JOIN cart_items ci ON c.cart_id = ci.cart_id
        """)
        rows = cursor.fetchall()

        carts_dict = {}
        for row in rows:
            cart_id = row['cart_id']
            product = { "id": row['id'], "qty": row['qty'] }

            if cart_id not in carts_dict:
                carts_dict[cart_id] = {
                    "cart_id": cart_id,
                    "products": [product]
                }
            else:
                carts_dict[cart_id]["products"].append(product)

        return jsonify(list(carts_dict.values())), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/cart/<string:cart_id>", methods=["PUT"])
@token_required
def update_product_qty_in_cart(cart_id):
    try:
        data = request.json
        product_id = data.get("id")
        new_qty = data.get("qty")

        if not product_id or not new_qty or new_qty <= 0:
            return jsonify({"error": "Invalid product ID or quantity"}), 400

        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT id FROM cart_items
            WHERE cart_id = %s AND product_id = %s
        """, (cart_id, product_id))
        item = cursor.fetchone()

        if not item:
            return jsonify({"error": "Product not found in cart"}), 404

        cursor.execute("""
            UPDATE cart_items
            SET qty = %s
            WHERE cart_id = %s AND product_id = %s
        """, (new_qty, cart_id, product_id))
        db.commit()

        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT product_id AS id, qty
            FROM cart_items
            WHERE cart_id = %s
        """, (cart_id,))
        items = cursor.fetchall()

        return jsonify({
            "cart_id": cart_id,
            "products": items
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/cart/<string:cart_id>", methods=["DELETE"])
@token_required
def delete_cart(cart_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT cart_id FROM carts WHERE cart_id = %s", (cart_id,))
        if not cursor.fetchone():
            return jsonify({"error": "Cart not found"}), 404

        cursor.execute("DELETE FROM cart_items WHERE cart_id = %s", (cart_id,))
        cursor.execute("DELETE FROM carts WHERE cart_id = %s", (cart_id,))
        db.commit()

        return jsonify({"message": "Cart deleted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/cart/<string:cart_id>", methods=["POST"])
@token_required
def add_product_to_cart(user, cart_id):
    try:
        data = request.json
        product_id = data.get("id")
        qty = data.get("qty")

        if product_id is None or qty is None or qty <= 0:
            return jsonify({"error": "Invalid product ID or quantity"}), 400

        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT cart_id FROM carts WHERE cart_id = %s", (cart_id,))
        if not cursor.fetchone():
            return jsonify({"error": "Cart not found"}), 404

        cursor.execute("""
            SELECT qty FROM cart_items
            WHERE cart_id = %s AND product_id = %s
        """, (cart_id, product_id))
        result = cursor.fetchone()

        if result:
            current_qty = result[0]
            new_qty = current_qty + qty
            cursor.execute("""
                UPDATE cart_items
                SET qty = %s
                WHERE cart_id = %s AND product_id = %s
            """, (new_qty, cart_id, product_id))
        else:
            cursor.execute("""
                INSERT INTO cart_items (cart_id, product_id, qty)
                VALUES (%s, %s, %s)
            """, (cart_id, product_id, qty))

        db.commit()

        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT product_id AS id, qty
            FROM cart_items
            WHERE cart_id = %s
        """, (cart_id,))
        items = cursor.fetchall()

        return jsonify({
            "cart_id": cart_id,
            "products": items
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/order", methods=["POST"])
@token_required
def place_order(user):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)

        user_id = user["id"]

        # 1. Get user's cart and existing order_ids
        cursor.execute("SELECT cart_id, order_id FROM user WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()

        if not user_data:
            return jsonify({"error": "User not found"}), 404

        cart_id = user_data.get("cart_id")
        order_ids = user_data.get("order_id")

        if not cart_id:
            return jsonify({"error": "No cart found"}), 400

        # Parse existing order_ids as JSON
        try:
            order_ids = json.loads(order_ids) if order_ids else []
        except json.JSONDecodeError:
            order_ids = []

        # 2. Get cart items and prices
        cursor.execute("""
            SELECT ci.product_id, ci.qty, p.price
            FROM cart_items ci
            JOIN products p ON ci.product_id = p.id
            WHERE ci.cart_id = %s
        """, (cart_id,))
        cart_items = cursor.fetchall()

        if not cart_items:
            return jsonify({"error": "Cart is empty"}), 400

        # 3. Calculate totals
        total_qty = sum(item['qty'] for item in cart_items)
        total_price = sum(item['qty'] * item['price'] for item in cart_items)

        # 4. Create new order
        order_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO orders (order_id, cart_id, total_qty, total_price, status)
            VALUES (%s, %s, %s, %s, %s)
        """, (order_id, cart_id, total_qty, total_price, "pending"))

        # 5. Add order items
        for item in cart_items:
            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, qty)
                VALUES (%s, %s, %s)
            """, (order_id, item["product_id"], item["qty"]))

        # 6. Update user: append order_id and clear cart
        order_ids.append(order_id)
        cursor.execute("""
            UPDATE user
            SET order_id = %s, cart_id = NULL
            WHERE id = %s
        """, (json.dumps(order_ids), user_id))

        # 7. Clear cart_items (optional but clean)
        cursor.execute("DELETE FROM cart_items WHERE cart_id = %s", (cart_id,))

        db.commit()

        return jsonify({
            "order_id": order_id,
            "cart_id": cart_id,
            "items": [{"id": i["product_id"], "qty": i["qty"]} for i in cart_items],
            "total_qty": total_qty,
            "total_price": total_price,
            "status": "pending"
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/orders", methods=["GET"])
@token_required
@admin_required
def get_orders():
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)

        cursor.execute("SELECT * FROM orders ORDER BY created_at DESC")
        orders_raw = cursor.fetchall()

        if not orders_raw:
            return jsonify([]), 200

        cursor.execute("""
            SELECT order_id, product_id AS id, qty
            FROM order_items
        """)
        items_raw = cursor.fetchall()

        items_map = {}
        for item in items_raw:
            items_map.setdefault(item['order_id'], []).append({
                "id": item["id"],
                "qty": item["qty"]
            })

        orders = []
        for order in orders_raw:
            orders.append({
                "order_id": order["order_id"],
                "cart_id": order.get("cart_id"),
                "items": items_map.get(order["order_id"], []),
                "total_qty": order["total_qty"],
                "total_price": float(order["total_price"]),
                "status": order["status"],
                "created_at": order["created_at"].isoformat()
            })

        return jsonify(orders), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    try:
        event = request.get_json()

        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            order_id = session.get('metadata', {}).get('order_id')

            if order_id:
                db = get_db()
                cursor = db.cursor()

                cursor.execute("""
                    UPDATE orders SET status = %s WHERE order_id = %s
                """, ("paid", order_id))
                db.commit()

                print(f"✅ Order {order_id} marked as paid.")
            else:
                print("⚠️ No order_id in metadata")

        return jsonify({'status': 'success'}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/orders/<string:order_id>", methods=["GET"])
@token_required
@admin_required
def get_order(order_id):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM orders WHERE order_id = %s", (order_id,))
        order = cursor.fetchone()

        if not order:
            return jsonify({"error": "Order not found"}), 404

        cursor.execute("""
            SELECT product_id AS id, qty
            FROM order_items
            WHERE order_id = %s
        """, (order_id,))
        items = cursor.fetchall()

        response = {
            "order_id": order["order_id"],
            "cart_id": order.get("cart_id"),
            "items": items,
            "total_qty": order["total_qty"],
            "total_price": float(order["total_price"]),
            "status": order["status"],
            "created_at": order["created_at"].isoformat()
        }

        return jsonify(response), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/create-checkout-session/<string:order_id>", methods=["POST"])
@token_required
def create_checkout_session(user, order_id):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)

        # Get order details
        cursor.execute("SELECT * FROM orders WHERE order_id = %s", (order_id,))
        order = cursor.fetchone()

        if not order:
            return jsonify({"error": "Order not found"}), 404

        # Get product details and quantity
        cursor.execute("""
            SELECT p.name, p.price, oi.qty
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            WHERE oi.order_id = %s
        """, (order_id,))
        items = cursor.fetchall()

        if not items:
            return jsonify({"error": "No items found for this order"}), 400

        line_items = []
        for item in items:
            line_items.append({
                "price_data": {
                    "currency": "usd",
                    "product_data": {
                        "name": item["name"],
                    },
                    "unit_amount": int(item["price"] * 100),
                },
                "quantity": item["qty"],
            })

        # Create checkout session
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="payment",
            line_items=line_items,
            success_url="http://localhost:3000/success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url="http://localhost:3000/cancel",
            metadata={"order_id": order_id}
        )

        return jsonify({"checkout_url": session.url}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
