CREATE TABLE transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    symbol TEXT NOT NULL,
    name TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    shares INTEGER NOT NULL,
    price NUMERIC NOT NULL,
    data TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT buy,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE UNIQUE INDEX transaction_id ON transactions (id);


CREATE TABLE stocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    symbol TEXT NOT NULL,
    name TEXT NOT NULL,
    tot_shares INTEGER NOT NULL,
    current_price NUMERIC NOT NULL,
    user_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);


