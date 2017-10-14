from flask import Flask, request, redirect, render_template, g, session
import requests
import boto3
from boto3.dynamodb.conditions import Key, Attr
from config import *
import time
import simplejson
from decimal import Decimal
from passlib.hash import sha256_crypt

boto_session = boto3.Session(aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY)

dynamodb = boto_session.resource('dynamodb', region_name='us-west-2')
db = dynamodb.Table('wtfindme')

app = Flask(__name__)
app.secret_key = APP_KEY


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def home():
    if 'logged_in' in session and session['logged_in']:
        profile = get_user_resources(session['username'])
        return render_template('home.html', profile=profile, username=session['username'])
    else:
        return redirect('/')
    
@app.route('/<username>/', methods = ['GET'])
def get_user_landing(username):
    links = get_user_links(username)
    if links:
        return simplejson.dumps(links)
    else:
        return "user doesn't exist"
        

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

@app.route('/profile', methods = ['GET'])
def get_profile():
    if 'logged_in' in session and session['logged_in']:
        resources = get_user_resources(session['username'])
        
    else:
        return 'not logged in', 403

@app.route('/register', methods = ['POST'])
def register():
    req = request.get_json()
    username = req['username']
    password = req['password']

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

    session['logged_in'] = True
    session['username'] = username
    return 'login success', 200


@app.route('/login', methods = ['POST'])
def login():
    req = request.get_json()
    username = req['username']
    password = req['password']

    p = db.get_item(
            Key = {'username' : username}
        )['Item']['password']

    if sha256_crypt.verify(password, p):
        session['logged_in'] = True
        session['username'] = username
        return 'login success', 200

    else:
        return 'login failed', 422
        
@app.route('/logout')
def logout():
    session['logged_in'] = False
    return redirect('/home')

def get_user_resources(username):
    response = db.get_item(
            Key = {'username' : username},
            ProjectionExpression = 'resources'
        )
    if 'Item' in response:
        return response['Item']['resources']
    else:
        return None

def get_user_links(username):
    resources = get_user_resources(username)
    if resources:
        links = {}
        for key, value in resources.iteritems():
            links[key] = value['link']
        return links
    else:
        return None
        
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


