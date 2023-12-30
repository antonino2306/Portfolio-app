import os
import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # return apology("TODO")
    # List of Dicts
    stocks_list = db.execute("SELECT symbol, name, shares, type FROM transactions WHERE user_id = ?", session['user_id'])

    current_price = {}
    tot_shares = {}
    symbols_list = []
    names_dict = {}
    stocks_dict = {}
    stocks_info = []

    # Get all the information to show in output and store them in a table called stocks
    for row in stocks_list:
        tmp = lookup(row['symbol'])
        current_price[row['symbol']] = tmp['price']

        if not row['symbol'] in symbols_list:
            symbols_list.append(row['symbol'])

        if not row['name'] in names_dict.values():
            names_dict[row['symbol']] = row['name']

        tot_shares[row['symbol']] = 0

    for row in stocks_list:
        if row['type'] == 'buy':
            tot_shares[row['symbol']] += row['shares']
        else:
            tot_shares[row['symbol']] -= row['shares']

    for el in symbols_list:
        stocks_dict['symbol'] = el
        stocks_dict['name'] = names_dict[el]
        stocks_dict['shares'] = tot_shares[el]
        stocks_dict['current_price'] = current_price[el]
        stocks_info.append(stocks_dict.copy())

    # If the users already owns a type of stock update only the number of shares and price
    # Else Insert into the database all the informations
    already_stocked = db.execute("SELECT symbol FROM stocks WHERE user_id = ?", session['user_id'])

    for row in stocks_info:
        if not any(s['symbol'] == row['symbol'] for s in already_stocked):
            db.execute("INSERT INTO stocks (symbol, name, tot_shares, current_price, user_id) VALUES (?, ?, ?, ?, ?)", row['symbol'], row['name'], row['shares'], row['current_price'], session['user_id'])
        else:
            db.execute("UPDATE stocks SET tot_shares = ?, current_price = ? WHERE symbol = ? and user_id = ?", row['shares'], row['current_price'], row['symbol'], session['user_id'])

    # List with one dict
    current_balance = db.execute("SELECT cash FROM users WHERE id = ?", session['user_id'])

    return render_template("index.html", stocks_info=stocks_info, current_balance=current_balance)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":

        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        try:
            shares = int(shares)
        except ValueError:
            return apology("Non numeric shares", 400)

        # Dict
        quote = lookup(symbol)

        if len(symbol) == 0 or quote == None:
            return apology("Insert a correct symbol", 400)

        if shares < 0:
            return apology("Invalid number of shares", 400)

        if not isinstance(shares, int):
            return apology("Invalid number of shares", 400)

        # Float
        stock_price = quote["price"]

        # List of dict with 1 element inside --> use user_cash[0]['cash'] to access the value
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

        total_price = stock_price * shares

        if user_cash[0]['cash'] < total_price:

            return apology("Insufficient money", 400)

        else:

            user_cash[0]['cash'] -= total_price

            # Insert transaction information in the database
            # Get current data
            timestamp = datetime.datetime.now()
            db.execute("INSERT INTO transactions (symbol, name, user_id, shares, price, data) VALUES (?, ?, ?, ?, ?, ?)", symbol.upper(), quote['name'], session['user_id'], shares, stock_price, timestamp)

            # Update user cash value in the database
            db.execute("UPDATE users SET cash = ? WHERE id = ?", user_cash[0]['cash'], session['user_id'])

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", session['user_id'])
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == 'POST':
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        if len(new_password) == 0 or len(confirmation) == 0:
            return apology("Empty field", 400)

        if not new_password == confirmation:
            return apology("Passwords don't match", 400)

        pw_hash = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=8)

        db.execute("UPDATE users SET hash = ? WHERE id = ?", pw_hash, session['user_id'])

        return redirect("/login")

    else:
        return render_template("change_password.html")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # Decide what to do based on the request method

    # POST
    if request.method == "POST":
        symbol = request.form.get("symbol")

        if len(symbol) == 0:
            return apology("No symbol inserted", 400)

        # Took information from the API using lookup function
        quote_info = lookup(symbol)

        if quote_info == None:
            return apology("Invalid symbol", 400)

        # Pass these data to the template to show them
        return render_template("quoted.html", company_name=quote_info['name'], quote=quote_info['price'], symbol=symbol)

    # GET
    else:
        # Load the template with the form
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Get all the users already registered
    user_list = db.execute("SELECT username FROM users")

    # POST
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Validation of form's values
        if len(username) == 0:
            return apology("Insert username", 400)

        if len(password) == 0 or len(confirmation) == 0:
            return apology("Insert password", 400)

        if any(user["username"] == username for user in user_list):

            return apology("This username already exists", 400)

        else:
            if password == confirmation:

                # Generate the hash of the password for more safety
                pw_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

                # Insert the user in the database
                db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, pw_hash)
                return redirect("/")

            else:
                return apology("Passwords doesn't match", 400)

    # GET
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # Select the symbols of the owned stacks to show them in the form in sell.html
    stacks_sym = db.execute("SELECT DISTINCT symbol FROM transactions WHERE user_id = ?", session['user_id'])

    if request.method == 'POST':
        # Get the symbol and the number of shares inserted by the user
        stock_selected = request.form.get("symbol")
        sell_shares = int(request.form.get("shares"))

        # Get the stock price via API call
        stocks_info = lookup(stock_selected)

        # Check for errors
        if stock_selected == None:
            return apology("Missing stack", 400)

        if sell_shares < 1:
            return apology("Invalid number", 400)

        owned_shares = db.execute("SELECT tot_shares FROM stocks WHERE user_id = ? AND symbol = ?", session['user_id'], stock_selected)
        # print(f"shares: {owned_shares}")

        if owned_shares[0]['tot_shares'] < sell_shares:
            return apology("Insufficient shares")

        # Update number of shares
        timestamp = datetime.datetime.now()
        db.execute("INSERT INTO transactions (symbol, name, user_id, shares, price, data, type) VALUES (?, ?, ?, ?, ?, ?, ?)", stock_selected, stocks_info['name'], session['user_id'], sell_shares, stocks_info['price'], timestamp, "sell")

        # Update cash
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

        total_price = stocks_info['price'] * sell_shares

        user_cash[0]['cash'] += total_price

        db.execute("UPDATE users SET cash = ? WHERE id = ?", user_cash[0]['cash'], session['user_id'])

        return redirect("/")

    else:
        return render_template("sell.html", stacks_sym=stacks_sym)

    # TODO:
