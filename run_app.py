# -*- coding: utf-8 -*-

import os

from api._01_basic_auth import app
# from api._02_custom_auth import app
# from api._03_jwt_auth import app


if __name__ == '__main__':
    app.debug = True
    app.config['DATABASE_NAME'] = 'auth.db'
    host = os.environ.get('IP', '0.0.0.0')
    port = int(os.environ.get('PORT', 8080))
    app.run(host=host, port=port)
