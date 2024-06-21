import datetime
import jwt
# JWT Token generation function
secret_key="sathvikasandha"
def generate_jwt(username):
    payload = {
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expires in 1 hour
    }
    token = jwt.encode(payload, secret_key, algorithm='HS256')
    return token