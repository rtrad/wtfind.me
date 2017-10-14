from itsdangerous import TimedJSONWebSignatureSerializer
from functools import wraps
from config import APP_KEY
from flask import request, g, jsonify

def generate_token(username, expires=1209600):
    s = TimedJSONWebSignatureSerializer(APP_KEY, expires_in=expires)
    token = s.dumps(username).decode('utf-8')
    return token
    
def verify_token(token):
    s = TimedJSONWebSignatureSerializer(APP_KEY)
    try:
        data = s.loads(token)
    except:
        return None
    return data

def authenticate(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authentication', None)
        if token:
            token = token.encode('ascii', 'ignore')
            username = verify_token(token)
            if username:
                g.username = username
                return f(*args, **kwargs)    
        return 'authentication required', 401
    return decorated
