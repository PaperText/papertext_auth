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
    * algo, default "pbkdf2_sha256,"\
        possible values:
        * argon2: newest hashing algorithm (since 2013)\
            support library: `pip install argon2-cffi`, 
            best choice
        * pbkdf2_sha256: has fastest pure-python backend\
            support library: `pip install fastpbkdf2`, 
            installed by default, but prefered for improved speed
            if pure python
        * bcrypt: most reliable, but not the fastest\
            support library: `pip install bcrypt`, required for use
* token (settings for jwt)
    * algo, default "ecdsa"\
        algorithm for jwt encoding, currently only ecdsa with secp521r1 curve is supported 
    * generate_keys, default false\
        generates key if none are present or if public is absent
    * regenerate_keys, default false\
        regenerates keys no matter what


