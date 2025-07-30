# Ecommerce Backend

A simple e-commerce backend built with Flask, MySQL, Stripe, and JWT authentication.

## Features

- User signup & login (JWT-based)
- Product CRUD (admin only)
- Cart management (add, update, delete, view)
- Order placement & history
- Stripe checkout integration
- Webhook for payment confirmation

## Setup

1. **Clone the repo**
   ```sh
   git clone https://github.com/yourusername/ecomm-backend.git
   cd ecommerce-backend
   ```

2. **Install dependencies**
   ```sh
   pip install -r requirements.txt
   ```

3. **Configure environment variables**

   Create a `.env` file:
   ```
   FLASK_SECRET_KEY=your_flask_secret
   STRIPE_API_KEY=your_stripe_key
   DB_HOST=localhost
   DB_USER=your_db_user
   DB_PASSWORD=your_db_password
   DB_NAME=your_db_name
   ```

4. **Run the app**
   ```sh
   python app.py
   ```

## API Endpoints

### Auth
- `POST /signup` — Register a new user
- `POST /login` — Login and get JWT token

### Products
- `GET /products` — List products
- `GET /products/<id>` — Get product details
- `POST /products` — Add product (admin)
- `PUT /products/<id>` — Update product (admin)
- `DELETE /products/<id>` — Delete product (admin)

### Cart
- `POST /cart/add` — Add product to user cart
- `GET /cart` — View all carts
- `PUT /cart/<cart_id>` — Update product quantity in cart
- `DELETE /cart/<cart_id>` — Delete cart
- `POST /cart/<cart_id>` — Add product to specific cart

### Orders
- `POST /order` — Place order from cart
- `GET /orders` — List all orders (admin)
- `GET /orders/<order_id>` — Get order details (admin)

### Stripe
- `POST /create-checkout-session/<order_id>` — Create Stripe checkout session
- `POST /webhook` — Stripe webhook for payment confirmation

## Notes

- All admin routes require JWT token with `role: admin`.
- Modularization is planned for future releases.
- Do not commit your `.env` file.

