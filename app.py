from flask import Flask, request, render_template, redirect, url_for, session, flash
import boto3
import json
import requests
import uuid
from botocore.exceptions import ClientError
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Configure AWS credentials and region
dynamodb = boto3.resource('dynamodb', region_name='ap-southeast-2')  
login_table = dynamodb.Table('login-taskmanagement-a3')
tasks_table = dynamodb.Table('tasksdata-taskmanagement-a3')

# Initialize the Lambda client
lambda_client = boto3.client('lambda', region_name='ap-southeast-2')
API_GATEWAY_URL = "https://6v6gcorg56.execute-api.ap-southeast-2.amazonaws.com/prod/register"

@app.route('/')
def index():
    return redirect(url_for('login'))  # Redirect root to login page
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    session.clear()
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Query DynamoDB to validate credentials
        response = login_table.get_item(Key={'email': email})

        # Check if the email exists and the password matches
        if 'Item' in response and response['Item']['password'] == password:
            # Set session for logged in user
            session['email'] = response['Item']['email']
            session['user_name'] = response['Item']['user_name']
            return redirect(url_for('home'))  # Redirect to the home page
        else:
            error = "email or password is invalid"
    
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        # Create payload for the API request
        payload = {
            "email": email,
            "username": username,
            "password": password
        }

        # Send the POST request to the API Gateway URL
        response = requests.post(API_GATEWAY_URL, json=payload)

        # Process the response from API Gateway
        if response.status_code == 200:
            flash("Registration successful. Please log in.")
            return redirect(url_for('login'))
        else:
            error = response.json().get("body", "An error occurred during registration")

    return render_template('register.html', error=error)

@app.route('/logout')
def logout():
    session.clear()  # Clear session data
    return redirect(url_for('login'))

@app.route('/home')
def home():
    if 'user_name' in session:
        user_name = session['user_name']
        return render_template('home.html', user_name=user_name)  # Send user_name to the home template
    else:
        return redirect(url_for('login'))  # Redirect to login if not logged in

@app.route('/create_task', methods=['GET', 'POST'])
def create_task():
    if request.method == 'POST':
        # Get form data
        task_name = request.form['task_name']
        task_description = request.form['task_description']
        task_due_date = request.form['task_due_date']
        assigned_to = request.form['assigned_to']
        task_status = "Pending"
        created_at = datetime.now().isoformat()
        
        task_id = str(uuid.uuid4())

        # Retrieve email from session (assuming user is logged in and email is stored in session)
        email = session.get('email')
        if not email:
            flash('You need to be logged in to create a task.', 'error')
            return redirect(url_for('login'))
        
        # Add the task to DynamoDB
        try:
            tasks_table.put_item(
                Item={
                     'email': email,
                     'task_id': task_id,
                     'task_name': task_name,
                     'task_description': task_description,
                     'task_due_date': task_due_date,
                     'assigned_to': assigned_to,
                     'task_status': task_status,
                     'created_at': created_at
                }
            )
            flash('Task created successfully!', 'success')
            return redirect(url_for('view_tasks'))
        except Exception as e:
            print(e)
            flash('Error creating task. Please try again.', 'error')
    
    # Render the task creation form if request is GET
    return render_template('create_task.html')

if __name__ == '__main__':
    app.run()


