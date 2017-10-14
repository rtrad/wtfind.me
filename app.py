from flask import Flask, request, jsonify, redirect, render_template, g
import requests
import boto3
from boto3.dynamodb.conditions import Key, Attr
from config import *
import time
from decimal import Decimal
from passlib.hash import sha256_crypt
from auth import generate_token, authenticate

boto_session = boto3.Session(aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY)

dynamodb = boto_session.resource('dynamodb', region_name='us-west-2')
db = dynamodb.Table('wtfindme')

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/<username>', methods = ['GET'])
def get_user_landing(username):
    return jsonify(get_user_resources(username))
        

@app.route('/<username>/<resource>', methods = ['GET'])
def redirect_user_resource(username, resource):
    resources = get_user_resources(username)
    if resource in resources:
        location = get_ip_info(request.remote_addr)
        referrer = request.referrer
        ts = Decimal(time.time())
        req = {'location' : location, 'referrer' : referrer, 'time' : ts}
        print req
        add_request(username, resource, req)
        return redirect(resources[resource]['link'])
    else:
        return redirect('/{}'.format(username))


@app.route('/register', methods = ['POST'])
def register():
    username = request.form['username']
    password = request.form['password']

    exists = db.query(
            KeyConditionExpression = Key('username').eq(username)
        )['Count'] > 0

    if exists:
        return 'user exists', 409
    
    password = sha256_crypt.encrypt(password)
    response = db.put_item(
            Item = {'username' : username, 'password' : password, 'resources' : {}},
            ConditionExpression = 'attribute_not_exists(username)'
        )

    return jsonify({'token' : generate_token(username)}), 200


@app.route('/login', methods = ['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    p = db.get_item(
            Key = {'username' : username}
        )['Item']['password']

    if sha256_crypt.verify(password, p):
        return jsonify({'token' : generate_token(username)}), 200

    else:
        return 'login failed', 422

def get_user_resources(username):
    response = db.get_item(
            Key = {'username' : username},
            ProjectionExpression = 'resources'
        )
    return response['Item']['resources']

def get_ip_info(address):
    response = requests.get('http://ipinfo.io/{}/geo'.format(address))
    response = response.json()
    del response['ip']
    return response

def add_request(username, resource, request):
    db.update_item(
            Key = {'username' : username},
            UpdateExpression = 'SET resources.{0}.requests = list_append(resources.{0}.requests, :i)'.format(resource),
            ExpressionAttributeValues = {':i' : [request]}
        )

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)


