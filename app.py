from flask import Flask, request, jsonify
import boto3
from config import *

boto_session = boto3.Session(aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY)

dynamodb = boto_session.resource('dynamodb', region_name='us-west-2')
users = dynamodb.Table('wtfindme-users')

app = Flask(__name__)



if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)


