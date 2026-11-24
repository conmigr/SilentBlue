def lookup(conn, name):
    conn.execute("SELECT * FROM users WHERE name = '" + name + "'")
