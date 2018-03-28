from flask import Flask
from flask import request, flash
from flask import render_template
from flask import session as login_session
from flask import url_for, redirect, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
from sqlalchemy import DateTime
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog App"


engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template("login.html", STATE=state)
    return "The current session state is %s" % login_session['state']


# Facebook login
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type\
           =fb_exchange_token&client_id=%s&\
           client_secret=%s&fb_exchange_token=%s'\
             % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we
        have to split the token first on commas and select the first index
        which gives us the key : value for the server access token then we
        split it on colons to pull out the actual token value and replace the
        remaining quotes with nothing so that it can be used directly in the
        graph api calls
    '''
    print "result obtain from api call with short token is: " + result
    token = result.split(',')[0].split(':')[1].replace('"', '')
    token = result.acessToken
    url = 'https://graph.facebook.com/v2.8/me?\
    access_token=%s&fields=name,id,email' % token

    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session
    # in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?\
    access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;\
    -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s'\
          % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Google login
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
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

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
                  'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # Add a new user if they do not exist in the database
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;\
              -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s'\
          % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps
                                 ('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
                   'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/')
def showcatalogRedirect():
    return redirect(url_for("showcatalog"))


@app.route('/catalog/')
def showcatalog():
    categories = session.query(Category).all()
    if 'username' not in login_session:
        return render_template('publicategories.html',
                               categories=categories)
    else:
        return render_template('categories.html', categories=categories)


# return "This creates a new category "
@app.route("/category/new", methods=["GET", "POST"])
def newCategory():
    if 'username' not in login_session:
        flash("You must be logged in to add a new category")
        return render_template('login.html')
    if request.method == "POST":
        name = request.form['name']
        user_id = login_session['user_id']
        newCategory = Category(name=name, user_id=user_id)
        session.add(newCategory)
        session.commit()
        flash("New category %s created" % name)
        return redirect(url_for("showcatalog"))
    else:
        return render_template("newcategory.html")


@app.route("/catalog/<string:category_name>/edit", methods=['GET', 'POST'])
def editCategory(category_name):
    editedCategory = session.query(Category).\
                     filter_by(name=category_name).one()
    creator = getUserInfo(editedCategory.user_id)
    action = 'edit'
    if 'username' not in login_session:
        flash("You must be logged in to edit a category")
        return render_template('login.html')
    elif login_session['user_id'] != creator.id:
        return render_template('authorization.html', action=action)
    if request.method == "POST":
        editedName = request.form['name']
        editedCategory.name = editedName
        session.add(editedCategory)
        session.commit()
        return redirect(url_for("showcatalog"))
    else:
        return render_template("editcategory.html",
                               editedCategory=editedCategory)


@app.route("/catalog/<string:category_name>/delete", methods=['GET', 'POST'])
def deleteCategory(category_name):
    deleteCategory = session.query(Category).\
                     filter_by(name=category_name).one()
    categoryName = deleteCategory.name
    creator = getUserInfo(deleteCategory.user_id)
    action = 'delete'
    if 'username' not in login_session:
        flash("You must be logged in to delete a category")
        return render_template('login.html')
    elif login_session['user_id'] != creator.id:
        return render_template('authorization.html', action=action)
    if request.method == "POST":
        session.delete(deleteCategory)
        session.commit()
        flash("Category %s has been deleted" % categoryName)
        return redirect(url_for("showcatalog"))
    else:
        return render_template("deletecategory.html",
                               deleteCategory=deleteCategory)


@app.route('/catalog/<string:category_name>/')
@app.route('/catalog/<string:category_name>/items')
def showCategoryItems(category_name):
    category = session.query(Category).filter_by(name=category_name).first()
    categoryItems = session.query(Item).filter_by(
                    category_id=category.id).all()
    creator = getUserInfo(category.user_id)
    if categoryItems:
        if 'username' not in login_session or\
                      creator.id != login_session['user_id']:
            return render_template("publicategoryitems.html",
                                   categoryItems=categoryItems,
                                   category_name=category_name)
        else:
            return render_template("categoryitems.html",
                                   categoryItems=categoryItems,
                                   category_name=category.name)
    else:
        if 'username' in login_session:
            return render_template("categoryitems.html",
                                   categoryItems=categoryItems,
                                   category_name=category.name)
        else:
            return render_template('publicategoryitems.html',
                                   category_name=category.name)


# return "This route provides a brief description of a particular item"
@app.route('/catalog/<string:category_name>/<string:item_name>')
def itemDescription(category_name, item_name):
    item = session.query(Item).filter_by(name=item_name).first()
    if item:
        return render_template("publicitemdescription.html", item=item)
    else:
        return redirect(url_for('showCategoryItems',
                                category_name=category_name))


@app.route("/catalog/<string:category_name>/new/", methods=['GET', 'POST'])
def newCategoryItem(category_name):
    category = session.query(Category).filter_by(name=category_name).first()
    categoryItems = session.query(Item).\
                    filter_by(category_id=category.id).all()
    creator = getUserInfo(category.user_id)
    if 'username' not in login_session:
        flash("You must be logged in to add a new item")
        return render_template('login.html')
    if request.method == 'POST':
        newItem = Item(name=request.form['name'],
                       description=request.form['description'],
                       category_id=category.id,
                       user_id=creator.id)
        session.add(newItem)
        session.commit()
        flash('New item %s Successfully Created' % (newItem.name))
        return redirect(url_for("showCategoryItems",
                                category_name=category.name))
    else:
        return render_template("newcategoryitem.html",
                               category_name=category.name)


@app.route("/catalog/<string:category_name>/<string:item_name>/edit/",
           methods=['GET', 'POST'])
def editCategoryItem(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).first()
    editedCategoryItem = session.query(Item).filter_by(name=item_name).first()
    creator = getUserInfo(category.user_id)
    if 'username' not in login_session or \
       creator.id != login_session['user_id']:
        flash("You must be logged in to edit an item")
        return redirect(url_for("showcatalog"))
    if request.method == "POST":
        editedName = request.form['name']
        editedDescription = request.form['description']
        editedCategoryItem.name = editedName
        editedCategoryItem.description = editedDescription
        session.add(editedCategoryItem)
        session.commit()
        flash("Item %s successfully edited" % editedCategoryItem.name)
        return redirect(url_for("showCategoryItems",
                                category_name=category_name))
    else:
        return render_template("editcategoryitem.html",
                               editedCategoryItem=editedCategoryItem,
                               category_name=category.name)


@app.route("/catalog/<string:category_name>/<string:item_name>/delete/",
           methods=['GET', 'POST'])
def deleteCategoryItem(category_name, item_name):
    deleteCategory = session.query(Category).\
                     filter_by(name=category_name).first()
    deleteCategoryItem = session.query(Item).filter_by(name=item_name).one()
    creator = getUserInfo(deleteCategory.user_id)
    if 'username' not in login_session or \
       creator.id != login_session['user_id']:
        flash("You must be logged in to edit an item")
        return render_template('login.html')
    if request.method == "POST":
        session.delete(deleteCategoryItem)
        session.commit()
        flash("item %s successfully removed" % deleteCategoryItem.name)
        return redirect(url_for("showCategoryItems",
                                category_name=category_name))
    else:
        return render_template("deletecategoryitem.html",
                               deleteCategory=deleteCategory,
                               deleteCategoryItem=deleteCategoryItem)


@app.route('/catalog.json')
def jsoncatalog():
    categories = session.query(Category).all()
    return jsonify(Categories=[i.serialize for i in categories])

    return 'This route shows all the categories in the catalog in json format'


@app.route('/catalog/<int:category_id>/items/json')
def jsoncatalogitems(category_id):
    items = session.query(Item).filter_by(category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/catalog/<int:item_id>/item/json')
def jsoncatalogitem(item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=item.serialize)


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showcatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showcatalog'))


if __name__ == '__main__':
    app.secret_key = "super_secret_key"
    app.debug = True
    app.run(host='0.0.0.0', port=80)
