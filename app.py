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

s3_client = boto3.client('s3', region_name='ap-southeast-2')
bucket_name = 'my-task-management-app-bucket-2024'

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
            session['profile_picture_url'] = response['Item']['profile_picture_url']
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
        task_status = "Incomplete"
        created_at = datetime.now().isoformat()
        
        task_id = str(uuid.uuid4())

        # Retrieve email from session
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

# Route to delete a task
@app.route('/delete_task/<task_id>', methods=['POST'])
def delete_task(task_id):
    try:
        # Remove task from DynamoDB based on task_id
        tasks_table.delete_item(
            Key={
                'email': session.get('email'),
                'task_id': task_id
            }
        )
        flash('Task deleted successfully!', 'success')
    except Exception as e:
        print(e)
        flash('Error deleting task. Please try again.', 'error')
    
    return redirect(url_for('view_tasks'))

# Route to edit a task
@app.route('/edit_task/<task_id>', methods=['GET', 'POST'])
def edit_task(task_id):
    # Fetch the task details from DynamoDB to populate the form
    task = tasks_table.get_item(
        Key={
            'email': session.get('email'),
            'task_id': task_id
        }
    ).get('Item')

    if request.method == 'POST':
        # Update the task details based on form input
        updated_task = {
            'email': session.get('email'),
            'task_id': task_id,
            'task_name': request.form['task_name'],
            'task_description': request.form['task_description'],
            'task_due_date': request.form['task_due_date'],
            'assigned_to': request.form['assigned_to'],
            'task_status': request.form['task_status'],
            'created_at': task['created_at']  # Keep the original creation date
        }
        
        # Save the updated task in DynamoDB
        tasks_table.put_item(Item=updated_task)
        flash('Task updated successfully!', 'success')
        return redirect(url_for('view_tasks'))
    
    return render_template('edit_task.html', task=task)

@app.route('/toggle_task_status/<task_id>', methods=['POST'])
def toggle_task_status(task_id):
    email = session.get('email')  # Retrieve email from session
    if not email:
        flash('You need to be logged in to update task status.', 'error')
        return redirect(url_for('login'))

    # Get the new status from the form
    new_status = request.form.get('new_status')

    try:
        # Update the task status in DynamoDB
        tasks_table.update_item(
            Key={'email': email, 'task_id': task_id},
            UpdateExpression="SET task_status = :status",
            ExpressionAttributeValues={':status': new_status}
        )
        flash('Task status updated successfully!', 'success')
    except Exception as e:
        print(e)
        flash('Error updating task status. Please try again.', 'error')

    return redirect(url_for('view_tasks'))

@app.route('/view_tasks')
def view_tasks():
    # Retrieve email from session
    email = session.get('email')
    if not email:
        flash('You need to be logged in to view tasks.', 'error')
        return redirect(url_for('login'))

    # Query DynamoDB to get all tasks for the logged-in user
    try:
        response = tasks_table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('email').eq(email)
        )
        tasks = response.get('Items', [])
    except Exception as e:
        print(e)
        flash('Error fetching tasks. Please try again.', 'error')
        tasks = []

    return render_template('view_tasks.html', tasks=tasks)

@app.route('/profile', methods=['GET'])
def profile():
    # Retrieve user's profile information
    email = session.get('email')
    if not email:
        flash('You need to be logged in to view your profile.', 'error')
        return redirect(url_for('login'))

    # Fetch user profile data from your database (DynamoDB or wherever it is stored)
    user_profile = login_table.get_item(Key={'email': email}).get('Item')
    session['profile_picture_url'] = user_profile.get('profile_picture_url', '')

    return render_template('profile.html', user_profile=user_profile)

@app.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    email = session.get('email')  # Retrieve email from session

    if request.method == 'POST':
        # Update user data
        new_username = request.form.get('username')
        selected_picture = request.form.get('profile_picture')

        try:
            # Update the user's profile picture URL and username in DynamoDB
            login_table.update_item(
                Key={'email': email},
                UpdateExpression="SET user_name = :username, profile_picture_url = :profile_picture",
                ExpressionAttributeValues={
                    ':username': new_username,
                    ':profile_picture': selected_picture
                }
            )
            session['profile_picture_url'] = selected_picture  # Update session with new picture URL
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            flash('Error updating profile. Please try again.', 'error')
            print(e)

        return redirect(url_for('profile'))

    # If GET, retrieve the current user's data
    user_data = login_table.get_item(Key={'email': email}).get('Item')

    # Fetch all images from the S3 bucket
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix="profile-pictures/")
        profile_pictures = [
            f"https://dsbctnf3cdxgu.cloudfront.net/{obj['Key']}"  # Generate CloudFront URLs
            for obj in response.get('Contents', [])
            if obj['Key'].endswith(('.jpg', '.png', '.jpeg'))  # Filter for image files
        ]
        if not profile_pictures:
            flash('No profile pictures found in the bucket.', 'info')
    except Exception as e:
        flash('Error retrieving profile pictures from S3.', 'error')
        print(e)
        profile_pictures = []

    return render_template(
        'update_profile.html',
        user_name=user_data['user_name'],
        email=email,
        profile_pictures=profile_pictures
    )


if __name__ == '__main__':
    app.run()


