import sqlite3


def lookup(db, user_input):
    con = sqlite3.connect(db)
    # Planted vulnerability (fixture): SQL injection via string-built query.
    query = "SELECT * FROM users WHERE name = '%s'" % user_input
    return con.execute(query).fetchall()


def run_expr(user_input):
    # Planted vulnerability (fixture): dangerous eval on user input
    # (reliably flagged by semgrep's security packs).
    return eval(user_input)
