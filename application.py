from functools import wraps
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash  
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Chocolates,Category, User
import random
import string
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog Application"


# Step 1: Create a database and ensure that connection is setup properly
# References for this entire piece of code : https://cloud.google.com/python/getting-started/authenticate-users
# https://github.com/mitsuhiko/flask-oauth/blob/master/example/google.py
# http://flask.pocoo.org/docs/0.12/tutorial/dbcon/
# https://stackoverflow.com/questions/16351826/link-to-flask-static-files-with-url-for
engine = create_engine('sqlite:///itemcatalogapp.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Write a login decorator
# Reference : https://pythonprogramming.net/decorator-wrappers-flask-tutorial-login-required/
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in login_session:
            return redirect(url_for('showLogin'))
        return f(*args, **kwargs)
    return decorated_function


# Retrieve catalog information, item detail and all items from database : JSON
# Reference for logic and catalog app : https://scotch.io/tutorials/build-a-crud-web-app-with-python-and-flask-part-one 
@app.route('/catalog.json')
def displayCatalogInfoJSON():
    items = session.query(CatalogItem).order_by(CatalogItem.id.desc())
    return jsonify(CatalogItems=[i.serialize for i in items])


@app.route('/categories/<int:category_id>/item/JSON')
def categoryChocolateJSON(category_id, catalog_item_id):
    Catalog_Item = session.query(
        CatalogItem).filter_by(id=catalog_item_id).one()
    return jsonify(Catalog_Item=Catalog_Item.serialize)


@app.route('/categories/JSON')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(Categories=[s.serialize for s in categories])

#Following CRUD pattern for Categories : Per Udacity Rubric
@app.route('/')
@app.route('/categories/')
def showCatalog():
    """Show Catalog : Categories and recently added items(chocolates) under each category"""
    categories = session.query(Category).all()
    items = session.query(Chocolates).order_by(Chocolates.id.desc())
    quantity = items.count()
    if 'username' not in login_session:
        return render_template(
            'catalog_inventory.html',
            categories=categories, items=items, quantity=quantity)
    else:
        return render_template(
            'catalog.html',
            categories=categories, items=items, quantity=quantity)


# Add a new category
@app.route('/categories/new', methods=['GET', 'POST'])
@login_required
def addnewCategory():
    if request.method == 'POST':
        print login_session
        if 'user_id' not in login_session and 'email' in login_session:
            login_session['user_id'] = getUserID(login_session['email'])
        newCategory = Category(
            name=request.form['name'],
            user_id=login_session['user_id'])
        session.add(newCategory)
        session.commit()
        flash("Success creating category!", 'success')
        return redirect(url_for('showCatalog'))
    else:
        return render_template('newCategory.html')


# Edit/Update an existing category
@app.route('/categories/<int:category_id>/edit/', methods=['GET', 'POST'])
@login_required
def editExistingCategory(category_id):
    editedCategory = session.query(
        Category).filter_by(id=category_id).one()
    if editedCategory.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You do not have permissions! Sorry')}</script><body onload='myFunction()'>"  
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
            flash(
                'Success editing category %s' % editedCategory.name,
                'success')
            return redirect(url_for('showCatalog'))
    else:
        return render_template(
            'editCategory.html', category=editedCategory)


# Delete an existing category
@app.route('/categories/<int:category_id>/delete/', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_id):
    categoryToDelete = session.query(
        Category).filter_by(id=category_id).one()
    if categoryToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You do not have permissions! Sorry')}</script><body onload='myFunction()'>"  
    if request.method == 'POST':
        session.delete(categoryToDelete)
        flash('%s Success deleting category' % categoryToDelete.name, 'success')
        session.commit()
        return redirect(
            url_for('showCatalog', category_id=category_id))
    else:
        return render_template(
            'deleteCategory.html', category=categoryToDelete)


#CRUD for chocolates (items)
# https://www.codementor.io/garethdwyer/building-a-crud-application-with-flask-and-sqlalchemy-dm3wv7yu2
@app.route('/categories/<int:category_id>/')
@app.route('/categories/<int:category_id>/items/')
def showCategoryList(category_id):
    """Lists items per category"""
    category = session.query(Category).filter_by(id=category_id).one()
    categories = session.query(Category).all()
    creator = getUserInfo(category.user_id)
    items = session.query(
        Chocolates).filter_by(
            category_id=category_id).order_by(Chocolates.id.desc())
    quantity = items.count()
    return render_template(
        'catalog_menu.html',
        categories=categories,
        category=category,
        items=items,
        quantity=quantity,
        creator=creator)


# Displays information about a particular item under a particular category
@app.route('/categories/<int:category_id>/item/<int:catalog_item_id>/')
def showChocolates(category_id, catalog_item_id):
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(
        Chocolates).filter_by(id=catalog_item_id).one()
    creator = getUserInfo(category.user_id)
    return render_template(
        'catalog_menu_item.html',
        category=category, item=item, creator=creator)


# Add a new chocolate
@app.route('/categories/item/new', methods=['GET', 'POST'])
@login_required
def newChocolate():
    categories = session.query(Category).all()
    if request.method == 'POST':
        addNewItem = Chocolates(
            name=request.form['name'],
            description=request.form['description'],
            category_id=request.form['category'],
            user_id=login_session['user_id'])
        session.add(addNewItem)
        session.commit()
        flash("New chocolate information added!", 'success')
        return redirect(url_for('showCatalog'))
    else:
        return render_template('newItem.html', categories=categories)


# Edit/Update chocolate information
@app.route(
    '/categories/<int:category_id>/item/<int:catalog_item_id>/edit',
    methods=['GET', 'POST'])
@login_required
def editChocolate(category_id, catalog_item_id):
    editedItem = session.query(
        Chocolates).filter_by(id=catalog_item_id).one()
    if editedItem.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You do not have permissions!Sorry!')}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['category']:
            editedItem.category_id = request.form['category']
        session.add(editedItem)
        session.commit()
        flash("Information has been updated!", 'success')
        return redirect(url_for('showCatalog'))
    else:
        categories = session.query(Category).all()
        return render_template(
            'editItem.html',
            categories=categories,
            item=editedItem)


# Delete Chocolate
@app.route(
    '/categories/<int:category_id>/item/<int:catalog_item_id>/delete',
    methods=['GET', 'POST'])
@login_required
def deleteChocolate(category_id, catalog_item_id):
    itemToDelete = session.query(
        Chocolates).filter_by(id=catalog_item_id).one()
    if itemToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You do not have permissions!Sorry!')}</script><body onload='myFunction()'>"  
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Information has been deleted', 'success')
        return redirect(url_for('showCatalog'))
    else:
        return render_template(
            'deleteItem.html', item=itemToDelete)


# Login
@app.route('/login')
def showLogin():
    state = ''.join(
        random.choice(
            string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

# Connection logic (Google)
@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data

    try:
        #Credentials object wil hold the authorization code
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Could not upgrade code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    #Access token validity check
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check if the user has the permissions to access
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token ID does not match. Denied!"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check app credibility access token
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Client ID does not match.Denied!"), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('User is connected'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Let session retain access token
    login_session['access_token'] = credentials.to_json()
    login_session['gplus_id'] = gplus_id

    # User info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['email'] = data['email']

    # check if user exists, if not , create a new user
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h3>Hello, '
    output += login_session['username']
    output += '!</h3>' 
    flash("Logged in as %s" % login_session['username'], 'success')
    print "done!"
    return output


# Revoke access and disconnect
@app.route('/gdisconnect')
def gdisconnect():
    # Check if user is connected, initiate disconnect
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('The user is not connected.'), 401)
        response.headers['Content-type'] = 'application/json'
        return response
    # Revoke token
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']

        response = make_response(json.dumps('Disconnect successful'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    else:
        response = make_response(
            json.dumps('Token cannot be revoked.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

# Helper functions listed below to aid with getting user info to setup or disconnect sessions and help determining access
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def createUser(login_session):
    newUser = User(
        name=login_session['username'],
        email=login_session['email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# Disconnect service
@app.route('/disconnect')
def disconnect():
    print login_session
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            if 'gplus_id' in login_session:
                del login_session['gplus_id']
            if 'credentials' in login_session:
                del login_session['credentials']
        if 'username' in login_session:
            del login_session['username']
        if 'email' in login_session:
            del login_session['email']
        if 'user_id' in login_session:
            del login_session['user_id']
        del login_session['provider']
        flash("Logged out now", 'success')
        return redirect(url_for('showCatalog'))
    else:
        flash("You don't seem to be logged in at all.", 'danger')
        return redirect(url_for('showCatalog'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
