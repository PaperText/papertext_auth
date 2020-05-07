PaperText Auth module
=====================

Configuration
-------------
* db (settings for db connection)
    * host, default "127.0.0.1"
    * port, default "5432"
    * username, default "postgres"
    * password: default "password"
    * dbname, default "papertext"
* hash (settings for password hashing)
    * algo, default "pbkdf2_sha512,"\
        possible values:
        * pbkdf2_sha512: has fastest pure-python backend\
            support library: `pip install fastpbkdf2`, 
            used by default, but preferred for improved speed
            in pure python implementation
        * argon2: newest(2013) hashing algorithm \
            support library: `pip install argon2-cffi`, 
            authors choice
        * bcrypt: most reliable, but not the fastest\
            support library: `pip install bcrypt`, required for use
* token (settings for jwt)
    * algo, default "ecdsa"\
        algorithm for jwt encoding, currently only ecdsa with secp521r1 curve is supported 
    * generate_keys, default false\
        generates key if none are present or if public is absent
    * regenerate_keys, default false\
        regenerates keys no matter what


