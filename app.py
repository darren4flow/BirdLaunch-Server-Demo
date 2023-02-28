from flask import Flask, request, jsonify, session
from flask_cors import CORS
import flask
import tweepy
import psycopg2
import datetime
import re
import docker
import json
from html import unescape, escape
from psycopg2.pool import SimpleConnectionPool
import stripe
from flask_session import Session
import boto3

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
CORS(app)
# --------------------------------------------
# Production configuration
endpoint_secret = ''
stripe.api_key = ""
new_campaign_url = "https://birdlaunch.io/new-campaign"
domain_name= "https://birdlaunch.io"
CALLBACK_URL = 'https://server.birdlaunch.io/callback'
pool = SimpleConnectionPool(
 1,
 10,
 host='',
 database='',
 user='',
 password='',
 port="5432"
)
# --------------------------------------------

# Twitter API Credentials
CONSUMER_TOKEN = ''
CONSUMER_SECRET = ''
ACCESS_TOKEN = ''
ACCESS_TOKEN_SECRET = ''

client = tweepy.Client(
  consumer_key=CONSUMER_TOKEN,
  consumer_secret=CONSUMER_SECRET,
  access_token=ACCESS_TOKEN,
  access_token_secret=ACCESS_TOKEN_SECRET
)


@app.route("/twitter/login")
def send_token():
    auth = tweepy.OAuthHandler(CONSUMER_TOKEN, CONSUMER_SECRET, CALLBACK_URL)
    print("came to login")
    try:
        # get the request tokens
        redirect_url = auth.get_authorization_url(signin_with_twitter=True)
        session['request_token'] = auth.request_token
        session['id'] = request.args.get("id")
    except tweepy.errors.TweepyException as e:
        print('Error! Failed to get request token')
    return flask.redirect(redirect_url)


@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
  try:
    checkout_session = stripe.checkout.Session.create(
      line_items=[
        {
          'price': 'price_1MOvf1F0BgsOHhUNbWWAQZ8n',
          'quantity': 1,
        },
      ],
      mode='subscription',
      success_url='{}/subscription'.format(domain_name) + '?success=true&session_id={CHECKOUT_SESSION_ID}',
      cancel_url='{}/'.format(domain_name) + '?canceled=true',
      customer_email=json.loads(request.data)['email'],
    )
    return jsonify(checkout_session.url)

  except Exception as e:
        print(e)
        return "Server error", 500



@app.route('/create-trial-checkout-session', methods=['POST'])
def create_trail_checkout_session():
  try:
    print(json.loads(request.data))
    prices = stripe.Price.list(
            lookup_keys=[json.loads(request.data)['lookup_key']], 
    expand=['data.product'])

    checkout_session = stripe.checkout.Session.create(
      line_items=[
        {
          'price': 'price_1MOvf1F0BgsOHhUNbWWAQZ8n',
          'quantity': 1,
        },
      ],
      mode='subscription',
      success_url='{}/subscription'.format(domain_name) + '?success=true&session_id={CHECKOUT_SESSION_ID}',
      cancel_url='{}/'.format(domain_name) + '?canceled=true',
      subscription_data={
        'trial_period_days': 3
      },
      customer_email=json.loads(request.data)['email'],
    )
    return jsonify(checkout_session.url)

  except Exception as e:
        print(e)
        return "Server error", 500



@app.route('/create-portal-session', methods=['POST'])
def customer_portal():
  try:
    # For demonstration purposes, we're using the Checkout session to retrieve the customer ID.
    # Typically this is stored alongside the authenticated user in your database.
    email = json.loads(request.data)['email']
    conn = pool.getconn()
    cur = conn.cursor()
    cur.execute("SELECT cus_id FROM subscriptions WHERE email='{}'".format(email))
    cus_id = cur.fetchone()[0]
    # This is the URL to which the customer will be redirected after they are
    # done managing their billing with the portal.
    return_url = '{}/subscription'.format(domain_name)

    portalSession = stripe.billing_portal.Session.create(
        customer=cus_id,
        return_url=return_url,
    )
    return jsonify(portalSession.url)
  except Exception as e:
    print(e)
    return "Server error", 500





def storeToken(id, token, secret, twitter_id, username):
  conn = pool.getconn()
  cur = conn.cursor()

  timestamp = datetime.datetime.now()
  #check if the twitter_id already exists
  try:
    cur.execute("CREATE TABLE IF NOT EXISTS msgd_{} (twitter_id text primary key, count int not null)".format(twitter_id))
    conn.commit()
  except:
    print("Error creating new messaged table for {}".format(username))
  try:
    cur.execute("CREATE TABLE IF NOT EXISTS leads_{} (twitter_id text primary key, username text not null, tag text default 'replied' not null, name TEXT, image TEXT);".format(twitter_id))
    conn.commit()
  except:
    print("Error creating new leads table for {}".format(username))
  try: 
    cur.execute("SELECT * FROM twitters WHERE twitter_id='{}'".format(twitter_id))
    if cur.rowcount == 0:
      #cur.execute("UPDATE twitters SET user_id = %s token = %s, secret = %s, username = %s auth_at = %s WHERE twitter_id = %s", (id, token, secret, username, timestamp, twitter_id))
    #else:
      cur.execute("INSERT INTO twitters (twitter_id, user_id, token, secret, username, auth_at) VALUES ('{}', '{}', '{}', '{}', '{}', '{}')".format(twitter_id, id, token, secret, username, timestamp))
      conn.commit()
      return True
  except:
    print("Error inserting token into database")
  finally:
    pool.putconn(conn)
  return False

@app.route("/twitter/callback")
def get_verification():
    # get the verifier key from the request url
    verifier = request.args['oauth_verifier']

    auth = tweepy.OAuthHandler(CONSUMER_TOKEN, CONSUMER_SECRET)
    token = session.get('request_token', 'Not Found')
    session.pop('request_token', None)

    auth.request_token = token

    try:
        auth.get_access_token(verifier)
    except tweepy.errors.TweepyException as e:
        print('Error! Failed to get access token.')

    # now you have access!
    api = tweepy.API(auth)
  
    # store in a db
    storeToken(str(session['id']), str(auth.access_token), str(auth.access_token_secret), str(api.verify_credentials()._json['id']), str(api.verify_credentials()._json['screen_name']))
    startCRM(str(auth.access_token), str(auth.access_token_secret), str(api.verify_credentials()._json['screen_name']))
    return flask.redirect(new_campaign_url)

def startCRM(access_token, access_token_secret, username):
  session = boto3.Session()
  aws_client = session.client('ecs', region_name='us-east-1')
  try:
    response = aws_client.run_task(
      cluster='BirdLaunch_Cluster',
      taskDefinition='arn:aws:ecs:us-east-1:278546699314:task-definition/BirdLaunch_sync_crm:1',
      count=1,
      launchType='EC2',
      tags=[
        {
          'key': 'owner',
          'value':username
        }
      ],
      overrides={
        'containerOverrides': [
          {
            'name': 'sync_crm',
            'environment': [
              {
                'name': 'ACCESS_TOKEN',
                'value': access_token
              },
              {
                'name': 'ACCESS_TOKEN_SECRET',
                'value': access_token_secret
              }
            ]
          }
        ]
      }
    )
  except:
    print("Error with starting container for CRM")
    return jsonify("Error with starting container for CRM")
  finally:
    del session
  return jsonify("CRM Started!")

@app.route('/health', methods=['GET'])
def config():
  return jsonify(status='Healthy')


@app.route('/check-subscription', methods=['GET'])
def checkSubscription():
  email = request.args.get("email")
  conn = pool.getconn()
  cur = conn.cursor()
  try:
    cur.execute("SELECT * FROM subscriptions WHERE email = '{}'".format(str(email)))
    if cur.rowcount > 0:
      record = cur.fetchone()
      if record[3] != None:
        return jsonify({'subscribed': 'is'})
      else:
        return jsonify({'subscribed': 'was'})
    else:
      print("no subscription found in database")
      return jsonify({'subscribed': 'never'})
  except:
    print("Error with checking if a user is subscribed")
  finally:
    pool.putconn(conn)
  return jsonify({'subscribed': 'error'})

@app.route('/webhook', methods=['POST'])
def webhook():
  event = None
  payload = request.data
  sig_header = request.headers['STRIPE_SIGNATURE']
  conn = pool.getconn()
  cur = conn.cursor()

  print("Webook triggered")
  try:
    event = stripe.Webhook.construct_event(
        payload, sig_header, endpoint_secret
    )
  except ValueError as e:
    # Invalid payload
    return e
  except stripe.error.SignatureVerificationError as e:
    # Invalid signature
    return e
  # Handle the event
  if event['type'] == 'customer.created':
    #Save the customer information in the subscriptions database
    email = event['data']['object']['email']
    cus_id = event['data']['object']['id']
    try:
      cur.execute("SELECT * FROM subscriptions WHERE email = '{}'".format(str(email)))
      if cur.rowcount > 0:
        cur.execute("UPDATE subscriptions SET cus_id = '{}' WHERE email = '{}'".format(cus_id, email))
        conn.commit()
      else:
        cur.execute("INSERT INTO subscriptions (cus_id, email) VALUES (%s, %s)", (cus_id, email))
        conn.commit()
    except:
      print("Error saving created customer in subscriptions table")
      jsonify(success=False)
    finally:
      pool.putconn(conn)
  elif event['type'] == 'customer.deleted':
    #Delete the customer information in the subscriptions database
    cus_id = event['data']['object']['id']
    try:
      cur.execute('DELETE FROM subscriptions WHERE cus_id = %s', (cus_id,))
      conn.commit()
    except:
      print("Error deleting customer from subscriptions database")
      jsonify(success=False)
    finally:
      pool.putconn(conn)
  elif event['type'] == 'customer.updated':
    #Update the customer information in the subscription database
    email = event['data']['object']['email']
    cus_id = event['data']['object']['id']
    try:
      cur.execute("UPDATE subscriptions SET email = %s WHERE cus_id = %s", ( email, cus_id))
      conn.commit()
    except:
      print("Error updating customer in subscriptions table")
      jsonify(success=False)
    finally:
      pool.putconn(conn)
  elif event['type'] == 'customer.subscription.created':
    #Save the subscription in the subscriptions database
    cus_id = event['data']['object']['customer']
    sub_id = event['data']['object']['id']
    try:
      cur.execute("UPDATE subscriptions SET sub_id = %s WHERE cus_id = %s", ( sub_id, cus_id))
      conn.commit()
    except:
      print("Error adding created subscription in subscriptions table")
      jsonify(success=False)
    finally:
      pool.putconn(conn)
  elif event['type'] == 'customer.subscription.deleted':
    #Delete the subscription in the subscriptions database
    cus_id = event['data']['object']['customer']
    try:
      conn = pool.getconn()
      cur = conn.cursor()
      docker_client = docker.from_env()
      session = boto3.Session()
      aws_client = session.client('cognito-idp', region_name='us-east-1')
      cur.execute("SELECT email from subscriptions where cus_id = '{}'".format(str(cus_id)))
      email = cur.fetchone()[0]
      user_id = aws_client.admin_get_user(UserPoolId='us-east-1_YbnJfea6a', Username=email)['Username']
      cur.execute("SELECT campaign_id, container_id from campaigns where user_id = '{}'".format(user_id))
      campaigns = cur.fetchall()
      for campaign in campaigns:
        campaign_id = campaign[0]
        container_id = campaign[1]
        container = docker_client.containers.get(str(container_id))
        container.stop()
        container.remove()
        cur.execute("DELETE FROM campaigns WHERE campaign_id = '{}'".format(campaign_id))
        conn.commit()
    except:
      print("Error with deleting campaigns after user unsubscribed")
      jsonify(success=False)
    finally:
      docker_client.close()
      pool.putconn(conn)
    try:
      conn = pool.getconn()
      cur = conn.cursor()
      cur.execute("UPDATE subscriptions SET sub_id = %s WHERE cus_id = %s", (None, cus_id))
      conn.commit()
    except:
      print("Error deleting subscription in subscriptions table")
      jsonify(success=False)
    finally:
      pool.putconn(conn)
    try:
      conn = pool.getconn()
      cur = conn.cursor()
      cur.execute("SELECT twitter_id from twitters where user_id = '{}'".format(str(user_id)))
      twitter_id = cur.fetchone()[0]
      cur.execute("DELETE FROM targets_{}".format(twitter_id))
      conn.commit()
    except:
      print("Error truncating targets table")
      jsonify(success=False)
    finally:
      pool.putconn(conn)

  elif event['type'] == 'customer.subscription.updated':
    #Update the subscription in the subscriptions database
    cus_id = event['data']['object']['customer']
    sub_id = event['data']['object']['id']
    try:
      cur.execute("UPDATE subscriptions SET sub_id = %s WHERE cus_id = %s", (sub_id, cus_id))
      conn.commit()
    except:
      print("Error updating subscription in subscriptions table")
      jsonify(success=False)
    finally:
      pool.putconn(conn)
  else:
    print('Unhandled event type {}'.format(event['type']))

  return jsonify(success=True)

@app.route('/authenticated', methods=['GET'])
def get_method():
  user_id = request.args.get("id")
  conn = pool.getconn()
  cur = conn.cursor()
  try:
    cur.execute("SELECT * FROM twitters WHERE user_id='{}'".format(str(user_id)))
    if cur.rowcount > 0:
      record = cur.fetchone()
      return jsonify(authenticated=True, username=record[5], serial_id=record[0])
    else:
      return jsonify(authenticated=False)
  except:
    print("Error checking if they have an authenticated twitter account")
  finally:
    pool.putconn(conn)
  return jsonify(authenticated=False)

@app.route('/updateleads', methods=['POST'])
def update_leads():
  user_id = request.get_json()['user_id']
  tag = request.get_json()['tag']
  twitter_id = request.get_json()['twitter_id']
  try:
    conn = pool.getconn()
    cur = conn.cursor()
    cur.execute("SELECT twitter_id FROM twitters WHERE user_id='{}'".format(str(user_id)))
    if cur.rowcount == 0:
      return jsonify("No twitter account")
    user_twitter_id = cur.fetchone()[0]
    cur.execute("UPDATE leads_{} SET tag = '{}' WHERE twitter_id = '{}'".format(str(user_twitter_id), tag, str(twitter_id)))
    conn.commit()
  except:
    print("Error with updating leads")
    return jsonify("Error with updating leads")
  finally:
    pool.putconn(conn)
  return jsonify("Updated Leads")


@app.route('/getleads', methods=['GET'])
def get_leads():
  user_id = request.args.get("id")
  leads = []
  try:
    conn = pool.getconn()
    cur = conn.cursor()
    cur.execute("SELECT twitter_id FROM twitters WHERE user_id='{}'".format(str(user_id)))
    if cur.rowcount == 0:
      return jsonify("No twitter account")
    twitter_id = cur.fetchone()[0]
    cur.execute("SELECT * from leads_{}".format(twitter_id))
    rows = cur.fetchall()
    for row in rows:
      leads.append({
        'twitter_id': row[0],
        'username': row[1],
        'tag': row[2],
        'name': row[3],
        'image': row[4]
      })
  except:
    print("Error with retrieving leads")
  finally:
    pool.putconn(conn)

  data = {'twitter_id': twitter_id, 'leads': leads}
  return jsonify(data)  

@app.route('/getcampaigns', methods=['GET'])
def get_campaigns():
  user_id = request.args.get("id")
  campaigns = []
  try:
    conn = pool.getconn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM campaigns WHERE user_id= %s", (user_id,))
    rows = cur.fetchall()
    docker_client = docker.from_env()
    for row in rows:
      container = docker_client.containers.get(str(row[2]))
      campaigns.append({
        'campaign_id': row[0],
        'user_id': row[1],
        'container_id': row[2],
        'twitter_username': row[3],
        'templates': row[4],
        'token': row[5],
        'secret': row[6],
        'target': row[7],
        'gender': row[8],
        'keywords': row[9],
        'negative_keywords': row[10],
        'min_limit': row[11][0],
        'max_limit': row[12][0],
        'status': container.status
      })
  except:
    print("Error with retrieving campaign records")
    return("Error with retrieving campaign records")
  finally:
    pool.putconn(conn)
    docker_client.close()
  return jsonify(campaigns)  
    

@app.route('/delete-auth', methods=['POST'])
def delete_auth():
  serial_id = request.get_json()['serial_id']
  print(serial_id)
  conn = pool.getconn()
  cur = conn.cursor()
  try:
    cur.execute('DELETE FROM twitters WHERE serial_id = %s', (serial_id,))
    conn.commit()
  except:
    print("Error deleting authentication record")
  finally:
    pool.putconn(conn)
  print("Authentication Deleted")
  return jsonify("Authentication Deleted")



@app.route('/deletecampaign', methods=['POST'])
def delete_campaign():
  campaign_id = request.get_json()['campaign_id']
  container_id = request.get_json()['container_id']
  conn = pool.getconn()
  cur = conn.cursor()
  docker_client = docker.from_env()
  try:
    cur.execute('DELETE FROM campaigns WHERE campaign_id = %s', (campaign_id,))
    conn.commit()
    container = docker_client.containers.get(str(container_id))
    container.stop()
    container.remove()
  except:
    print("Error with deleting campaign record")
    return jsonify("Error with deleting campaign record")
  finally:
    pool.putconn(conn)
    docker_client.close()
  print("Campaign Deleted")
  return jsonify("Campaign Deleted")


@app.route('/editcampaign', methods=['POST'])
def edit_campaign():
  # I want to use the data in request.json to update the campaigns record to use the new templates.
  conn = pool.getconn()
  cur = conn.cursor()
  data = request.get_json()

  # Validate the min and max limit input
  maxLimit_wc = data['maxLimit'].replace(",", "")
  minLimit_wc = data['minLimit'].replace(",", "")
  if data['maxLimit'] != '':
    if not maxLimit_wc.isdigit():
      return jsonify('Error with Min Follower Limit')
    if (int(maxLimit_wc) < 1):
      return jsonify('Error with Max Follower Limit')
  if data['maxLimit'] != '':
    if not minLimit_wc.isdigit():
      return jsonify('Error with Max Follower Limit')
    if (int(minLimit_wc) < 0):
      return jsonify('Error with Min Follower Limit')

  for template in data['templates']:
    if ('{}' not in template):
      print("One or more message templates don't include personalization")
      return jsonify("No Personalization")

  if re.search(r',,', data['keywords']):
    print("Remove extra comma")
    return jsonify("Remove extra comma from keywords")


  if (len(data['keywords']) > 0 ):
    if data['keywords'][-1] == ",":
      print("Remove extra comma")
      return jsonify("Remove extra comma from keywords")
  
    #I want to check that the keywords don't have consecutive commas
  if re.search(r',,', data['negative_keywords']):
    print("Remove extra comma from negative keywords")
    return jsonify("Remove extra comma from negative keywords")


  if (len(data['negative_keywords']) > 0 ):
    if data['negative_keywords'][-1] == ",":
      print("Remove extra comma from negative keywords")
      return jsonify("Remove extra comma from from negative keywords")

  try:
    keywords = re.sub(r'\s*,\s*', ',', data['keywords']).split(",")
    negative_keywords = re.sub(r'\s*,\s*', ',', data['negative_keywords']).split(",")
    cur.execute("UPDATE campaigns SET templates = %s, keywords = %s, negative_keywords = %s, gender = %s, min_limit = %s, max_limit = %s WHERE campaign_id = %s", (data['templates'], keywords, negative_keywords, data['gender'],[minLimit_wc], [maxLimit_wc], data['campaign_id']))
    conn.commit()
  except:
    print("Error with updating campaign record")
    return jsonify("Error with updating campaign record")
  finally:
    pool.putconn(conn)

  print("Campaign Updated")
  return jsonify("Campaign Updated")


@app.route('/startcampaign', methods=['POST'])
def start_campaign():
  data = request.get_json()

  # Validate the min and max limit input
  maxLimit_wc = data['max_limit'].replace(",", "")
  minLimit_wc = data['min_limit'].replace(",", "")
  if data['max_limit'] != '':
    if not maxLimit_wc.isdigit():
      return jsonify('Error with Min Follower Limit')
    if (int(maxLimit_wc) < 1):
      return jsonify('Error with Max Follower Limit')
  if data['min_limit'] != '':
    if not minLimit_wc.isdigit():
      return jsonify('Error with Max Follower Limit')
    if (int(minLimit_wc) < 0):
      return jsonify('Error with Min Follower Limit')


  # This will get the a
  try :
    target = client.get_user(username=data['target'], user_auth=True)
    if target.data is None:
      print("Invalid Target Username")
      return jsonify("Invalid Target Username")
  except:
    print("Error validating target username")
    return jsonify("Invalid Target Username")

  #I want to check that the keywords don't have consecutive commas
  if re.search(r',,', data['keywords']):
    print("Remove extra comma")
    return jsonify("Remove extra comma from keywords")


  if (len(data['keywords']) > 0 ):
    if data['keywords'][-1] == ",":
      print("Remove extra comma")
      return jsonify("Remove extra comma from keywords")
  
    #I want to check that the keywords don't have consecutive commas
  if re.search(r',,', data['negative_keywords']):
    print("Remove extra comma from negative keywords")
    return jsonify("Remove extra comma from negative keywords")


  if (len(data['negative_keywords']) > 0 ):
    if data['negative_keywords'][-1] == ",":
      print("Remove extra comma from negative keywords")
      return jsonify("Remove extra comma from from negative keywords")

  # I need the server to save the templates in the campaigns table
  try: 
    # Create a list of the messages
    msg_templates = []
    for message in data['messages']:
      if ('{}' in message['value']):
        msg_templates.append(message['value'])
      else:
        print("One or more messages missing personalization")
        return jsonify("One or more messages missing personalization")

    #Create an escaped keywords string

    keywords = re.sub(r'\s*,\s*', ',', data['keywords']).split(",")
    negative_keywords = re.sub(r'\s*,\s*', ',', data['negative_keywords']).split(",")
  except:
    print("error with accessing data")
    return jsonify("Error with accessing data")

  docker_client = docker.from_env()
  conn = pool.getconn()
  cur = conn.cursor()

  try:
    cur.execute("SELECT * FROM twitters WHERE user_id = '{}'".format(data['user_id']))
    record = cur.fetchone()
    print("Printing record: {}".format(record))
    if record is None: 
      return jsonify("Not authenticated")

    cur.execute("INSERT INTO campaigns \
      (user_id, twitter_username, templates, token, secret, target, gender, keywords, negative_keywords, min_limit, max_limit) \
      VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING campaign_id", (data['user_id'],record[5], msg_templates, record[3], record[4], data['target'], data['gender'], keywords, negative_keywords, [minLimit_wc], [maxLimit_wc],))
    campaign_id = cur.fetchone()[0]
    conn.commit()
  except:
    print("Campaign Record Already Exists")
    pool.putconn(conn)
    return jsonify("Campaign Record Already Exists")

  try:
    container = docker_client.containers.run(
      image='campaign_image:3',
      environment={
          'ACCESS_TOKEN': str(record[3]),
          'ACCESS_TOKEN_SECRET': str(record[4]),
          'TARGET': str(data['target']),
          'GENDER': str(data['gender']),
          'CAMPAIGN_ID': str(campaign_id)
      },
      stdout=True, 
      stderr=True,
      detach=True,
      privileged=True   
    )
    cur.execute("UPDATE campaigns SET container_id = %s WHERE campaign_id = %s", (container.id, campaign_id))
    conn.commit()
  except:
    print("Error with starting a container or updating the campaign record with the container ID")
    pool.putconn(conn)
    return jsonify("Error with starting a container or updating the campaign record with the container ID")
  finally:
    docker_client.close()
  
  pool.putconn(conn)
  return jsonify("Campaign Started!")



if __name__ == "__main__":
    app.run()
