from flask import Flask, request, redirect, url_for, render_template, jsonify, flash, session, json
from flask_sqlalchemy import SQLAlchemy
from flask_modus import Modus
from flask_moment import Moment
from flask_marshmallow import Marshmallow
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
import os
import re
from werkzeug.utils import secure_filename
import PIL
from PIL import Image
from datetime import date
import dropbox
from xhtml2pdf import pisa
import datetime
from flask_debugtoolbar import DebugToolbarExtension
import email, ssl, smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pyqrcode import QRCode
from babel.numbers import format_currency 
import requests
import math

app = Flask(__name__,
            static_url_path='', 
            static_folder='static')


app.config.from_object(os.environ['APP_SETTINGS'])
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SQLALCHEMY_POOL_RECYCLE"] = 3600
modus = Modus(app)
db = SQLAlchemy(app)
ma = Marshmallow(app)
moment = Moment()
bcrypt = Bcrypt(app)
toolbar = DebugToolbarExtension(app)

from token2 import generate_confirmation_token, confirm_token


@app.template_filter()
def usdollar(value):
   return format_currency(value, 'USD', locale='en_US')

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

path = os.getcwd()
#path = os.path.dirname(__file__)
# file Upload
UPLOAD_FOLDER = os.path.join(path, 'static/uploads')

if not os.path.isdir(UPLOAD_FOLDER):
    os.mkdir(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
 
from models import User, InvoiceData, InvoiceItems, ImageData, InvoiceValues, ProfileData, TemplateData, TemplateHTMLData, QRcodeData

class InvoiceDataSchema(ma.SQLAlchemyAutoSchema):
        class Meta:
            model = InvoiceData
            load_instance = True

# setup the login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

         
####  setup routes  ####
@app.route('/')
def index():
    return render_template('index.html')
    
@app.route('/appindex')
@login_required
def appindex():
    return render_template('app-index.html', user=current_user)
    
@app.route('/appabout')
@login_required
def appabout():
    return render_template('appabout.html', user=current_user)
    
@app.route('/about')
def about():
    return render_template('about.html')
    
def is_human(captcha_response):
    """ Validating recaptcha response from google server
        Returns True captcha test passed for submitted form else returns False.
    """
    secret = app.config['SECRET_SITE_KEY']
    payload = {'response':captcha_response, 'secret':secret}
    response = requests.post("https://www.google.com/recaptcha/api/siteverify", payload)
    response_text = json.loads(response.text)
    return response_text['success']
    
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    sitekey = app.config['RECAPTCHA_SITE_KEY']
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        captcha_response = request.form['g-recaptcha-response']
    
        if not is_human(captcha_response):
            # Log invalid attempts
            status = "Sorry ! Please Check Im not a robot."
            flash(status, "warning")
            return render_template('contact.html', sitekey=sitekey)
        else:    
            #send contact mail
            html = "<html><head></head><body>"
            html += "<p>Name: " + name + "</p>"
            html += "<p>Email: " + email + "</p>"
            html += "<p>Subject: " + subject + "</p>"
            message = "<br />".join(message.split("\n"))
            html += "<p>Message: <br /><br />" + message + "</p>"
            html += "</body></html>"
        
            body = html
            email_username = app.config['MAIL_USERNAME']
            sender_email = app.config['MAIL_DEFAULT_SENDER']
            receiver_email = "jctyasociados@gmail.com"
            password = app.config['MAIL_PASSWORD']

            # Create a multipart message and set headers
            message = MIMEMultipart()
            message["From"] = "IOL Invoice " + '<' + sender_email + '>'
            message["To"] = receiver_email
            message["Subject"] = subject
            #message["Bcc"] = receiver_email  # Recommended for mass emails

            # Add body to email
            message.attach(MIMEText(body, "html"))

            #text = message.as_string()
            """"connection = smtplib.SMTP(host='smtp.office365.com', port=587)
            connection.starttls()
            connection.login(email_username,password)
            connection.send_message(message)
            connection.quit()"""

            server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
            server.login(email_username, password)
            server.sendmail(sender_email, receiver_email, message.as_string())
            server.quit()
        
            return render_template('contact-form-sent.html')
    
    return render_template('contact.html', sitekey=sitekey)
    
@app.route('/appcontact', methods=['GET', 'POST'])
@login_required
def appcontact():
    sitekey = app.config['RECAPTCHA_SITE_KEY']
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        captcha_response = request.form['g-recaptcha-response']
    
        if not is_human(captcha_response):
            # Log invalid attempts
            status = "Sorry ! Please Check Im not a robot."
            flash(status, "warning")
            return render_template('appcontact.html', sitekey=sitekey, user=current_user)
        else:
            #send contact mail
            html = "<html><head></head><body>"
            html += "<p>Name: " + name + "</p>"
            html += "<p>Email: " + email + "</p>"
            html += "<p>Subject: " + subject + "</p>"
            message = "<br />".join(message.split("\n"))
            html += "<p>Message: <br /><br />" + message + "</p>"
            html += "</body></html>"
        
            body = html
            email_username = app.config['MAIL_USERNAME']
            sender_email = app.config['MAIL_DEFAULT_SENDER']
            receiver_email = "jctyasociados@gmail.com"
            password = app.config['MAIL_PASSWORD']

            # Create a multipart message and set headers
            message = MIMEMultipart()
            message["From"] = "IOL Invoice " + '<' + sender_email + '>' 
            message["To"] = receiver_email
            message["Subject"] = subject
            #message["Bcc"] = receiver_email  # Recommended for mass emails

            # Add body to email
            message.attach(MIMEText(body, "html"))

            #text = message.as_string()
            """connection = smtplib.SMTP(host='smtp.office365.com', port=587)
            connection.starttls()
            connection.login(email_username,password)
            connection.send_message(message)
            connection.quit()"""

            server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
            server.login(email_username, password)
            server.sendmail(sender_email, receiver_email, message.as_string())
            server.quit()
        
        
            return render_template('app-contact-form-sent.html', user=current_user)
    
    return render_template('appcontact.html', sitekey=sitekey, user=current_user)
    
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    user_hashed=current_user.user_id_hash
    found_image_data = db.session.query(ImageData).filter_by(user_id=(user_hashed)).first()
    
    #user_id = current_user.user_id_hash
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file selected for uploading')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            extension=filename.split(".")
            extension=str(extension[1])
            name=current_user.user_id_hash
            name=name.replace("/","$$$")
            name=name.replace(".","$$$")
            destination=name+"orig"+"."+extension
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], destination))
            
            image = PIL.Image.open(os.path.join(app.config['UPLOAD_FOLDER'], destination))
            
            width, height = image.size
            
            #print(width, height)
            finalimagename=name+"."+extension 
            baseheight = 106
            if height > 106:
                ratio = width / height
                img = Image.open(os.path.join(app.config['UPLOAD_FOLDER'], destination))
                nheight = 106
                basewidth = int(ratio * nheight)
                img = img.resize((basewidth, nheight), Image.ANTIALIAS)
                img.save(os.path.join(app.config['UPLOAD_FOLDER'], finalimagename))
                new__image = PIL.Image.open(os.path.join(app.config['UPLOAD_FOLDER'], finalimagename))
                width, height = new__image.size
            else:
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], finalimagename))
                width, height = image.size
                   
            upload_path = "static/uploads"
            os.chdir(upload_path)
            os.remove(destination)
            
                       
                       
            os.chdir(r"../..")
            name_url_final = "https://iol-accountant.onrender.com" + "/static/uploads" + "/" + finalimagename

            user_hashed=current_user.user_id_hash
            
            found_image_data = db.session.query(ImageData).filter_by(user_id=(user_hashed)).all()
            for row in found_image_data:
                ImageData.query.delete()
                db.session.commit()
            
            new_image = ImageData(user_hashed, finalimagename, name_url_final, width, height)
            db.session.add(new_image)
            db.session.commit()
            
            
            flash('File successfully uploaded')
            return redirect('/upload')
        else:
            flash('Allowed file types are png, jpg, jpeg, gif')
            return redirect(request.url)
    return render_template('upload.html', user=current_user)

@app.route("/send_html")
@login_required

def send_html():
    user_hashed=current_user.user_id_hash
    
    found_profile_data = db.session.query(ProfileData).filter_by(user_id=(user_hashed)).first() 
    #found_template_html_data = db.session.query(TemplateHTMLData).filter_by(user_id=(user_hashed)).first()
    #found_template_data = db.session.query(TemplateData).filter_by(user_id=(user_hashed)).first()
    found_invoice_data = db.session.query(InvoiceData).filter_by(user_id=(user_hashed)).first()     
    user_hashed=current_user.user_id_hash
    name=user_hashed
    name=name.replace("/","$$$")
    name=name.replace(".","$$$")
    
    subject = "Invoice from" + " " + found_profile_data.businessname
    file = open(app.config['UPLOAD_FOLDER'] + "/email" + name + ".html", "r")
    body = file.read()
    file.close()
    
    email_username = app.config['MAIL_USERNAME']
    sender_email = app.config['MAIL_DEFAULT_SENDER']
    receiver_email = found_invoice_data.email
    password = app.config['MAIL_PASSWORD']
    
    # Create a multipart message and set headers
    message = MIMEMultipart()
    message["From"] = "IOL Invoice" + '<' + sender_email + '>'
    message["To"] = receiver_email
    message["Subject"] = subject
    #message["Bcc"] = sender_email  # Recommended for mass emails
    
    # Add body to email
    message.attach(MIMEText(body, "html"))
    
        
    
    name=user_hashed
    name=name.replace("/","$$$")
    name=name.replace(".","$$$")
    
    filename_app = app.config['UPLOAD_FOLDER'] + "/" + name + ".pdf"
    
    # Open PDF file in binary mode
    
    #pdfname = 'writings.pdf'

    # open the file in bynary
    binary_pdf = open(filename_app, 'rb')

    payload = MIMEBase('application', 'octate-stream', Name=filename_app)
    # payload = MIMEBase('application', 'pdf', Name=pdfname)
    payload.set_payload((binary_pdf).read())

    # enconding the binary into base64
    encoders.encode_base64(payload)

    # add header with pdf name
    payload.add_header('Content-Decomposition', 'attachment', filename=filename_app)
    message.attach(payload)
    #text = message.as_string()

    #use gmail with port
    """connection = smtplib.SMTP(host='smtp.office365.com', port=587)
    connection.starttls()
    connection.login(email_username,password)
    connection.send_message(message)
    connection.quit()"""

    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    server.login(email_username, password)
    server.sendmail(sender_email, receiver_email, message.as_string())
    server.quit()
    
    return render_template('email_sent.html', user=current_user)    



@app.route("/login", methods=["GET", "POST"])
def login():
    sitekey = app.config['RECAPTCHA_SITE_KEY']


    # clear the inital flash message
    session.clear()
    if request.method == 'GET':
        return render_template('login.html', sitekey=sitekey)
    if request.method == 'POST':
        # get the form data
        username = request.form['username']
        password = request.form['password']
        captcha_response = request.form['g-recaptcha-response']
         
        remember_me = False
        if 'remember_me' in request.form:
            remember_me = True
        
        

        # query the user
        registered_user = User.query.filter_by(username=username).first()

        # check the passwords
        if registered_user is None:
            flash("Invalid Username", "warning")
            return render_template('login.html', sitekey=sitekey)
        
        if registered_user.username == username and bcrypt.check_password_hash(registered_user.password, password) == False:
            
            flash("Invalid Password", "warning")
            return render_template('login.html', sitekey=sitekey)
        
        if not is_human(captcha_response):
            # Log invalid attempts
            status = "Sorry ! Please Check Im not a robot."
            flash(status, "warning")
            return render_template('login.html', sitekey=sitekey)
        #return redirect(url_for('login'))

        # login the user
        
        if registered_user.username == username and bcrypt.check_password_hash(registered_user.password, password) == True and registered_user.confirmed == False:
            flash("You have to confirm your email.", "warning")
            return render_template('login.html', sitekey=sitekey)
        elif registered_user.username == username and bcrypt.check_password_hash(registered_user.password, password) == True and registered_user.confirmed == True:
    	    login_user(registered_user, remember=remember_me)  
        return redirect(request.args.get('next') or url_for('appindex'))
    
    	      	
@app.route('/recover', methods=["GET", "POST"])
def recover():
    sitekey = app.config['RECAPTCHA_SITE_KEY']
    if request.method == 'GET':
        session.clear()
        return render_template('password-recover.html', sitekey=sitekey)
        
    username = request.form['username']
    captcha_response = request.form['g-recaptcha-response']
    
    if not is_human(captcha_response):
            # Log invalid attempts
            status = "Sorry ! Please Check Im not a robot."
            flash(status, "warning")
            return render_template('password-recover.html', sitekey=sitekey)
    
    found_user = db.session.query(User).filter_by(username=username).first()
    if found_user:
      token = generate_confirmation_token(found_user.email)
      confirm_url = url_for('password_reset', token=token, username=username, _external=True)
      html = render_template('recovery.html', confirm_url=confirm_url)
      subject = "Please reset your password"
      #send_email(user.email, subject, html)
      # query the user
      #registered_user = User.query.filter_by(username=user.username).first()
      #login_user(user)
      #login_user(registered_user)

      
      body = html
      email_username = app.config['MAIL_USERNAME']
      sender_email = app.config['MAIL_DEFAULT_SENDER']
      password = app.config['MAIL_PASSWORD']

      # Create a multipart message and set headers
      message = MIMEMultipart()
      message["From"] = "IOL Invoice" + '<' + sender_email + '>'
      message["To"] = found_user.email
      message["Subject"] = subject
      #message["Bcc"] = receiver_email  # Recommended for mass emails

      # Add body to email
      message.attach(MIMEText(body, "html"))

      #text = message.as_string()
      #use outlook with port
      """sessionsmtp = smtplib.SMTP('smtp.office365.com', 587)
      sessionsmtp.ehlo()
      #enable security
      sessionsmtp.starttls()

      #login with mail_id and password
      sessionsmtp.login(email_username, password)

      text = message.as_string()
      sessionsmtp.sendmail(sender_email, found_user.email, text)
      sessionsmtp.quit()"""

      server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
      server.login(email_username, password)
      server.sendmail(sender_email, found_user.email, message.as_string())
      server.quit()

      flash("A Reset Password email has been sent via email.", "success")
      return render_template('password-recover.html', sitekey=sitekey )
        #flash("Account Created")
        #return redirect(url_for('login'))
      print(found_user.email)
      return render_template('password-recover.html', sitekey=sitekey)
    else:
      flash("Username not found","warning")
      return render_template('password-recover.html', sitekey=sitekey)
          	

@app.route('/registration', methods=["GET", "POST"])
def register():
    sitekey = app.config['RECAPTCHA_SITE_KEY']
    if request.method == 'GET':
        session.clear()
        return render_template('register.html', sitekey=sitekey)

    # get the data from our form
    password = request.form['password']
    conf_password = request.form['confirm-password']
    username = request.form['username']
    email = request.form['email']
    captcha_response = request.form['g-recaptcha-response']
    
    
    if not is_human(captcha_response):
        # Log invalid attempts
        status = "Sorry ! Please Check Im not a robot."
        flash(status, "warning")
        return render_template('register.html', sitekey=sitekey)
    # make sure the password match
    if conf_password != password:
        flash("Passwords do not match", "warning")
        return render_template('register.html', sitekey=sitekey)

    # check if it meets the right complexity
    check_password = password_check(password)

    # generate error messages if it doesnt pass
    if True in check_password.values():
        for k,v in check_password.items():
            if str(v) == "True":
                flash(k, "warning")

        return render_template('register.html', sitekey=sitekey)
    # hash the password for storage
    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    user_id_hashed = bcrypt.generate_password_hash(username).decode('utf-8')
    #mobile phone
    #pw_hash = bcrypt.generate_password_hash(password)
    #user_id_hashed = bcrypt.generate_password_hash(username)
    # create a user, and check if its unique
    user = User(username, user_id_hashed, pw_hash, email, confirmed=False)
    u_unique = user.unique()
    

    

    # add the user
    if u_unique == 0:
        db.session.add(user)
        db.session.commit()
        token = generate_confirmation_token(user.email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('activate.html', confirm_url=confirm_url)
        subject = "Please confirm your email"
        #send_email(user.email, subject, html)
        # query the user
        #registered_user = User.query.filter_by(username=user.username).first()
        #login_user(user)
        #login_user(registered_user)

        subject = "Confirm Your Registration"
        body = html
        email_username = app.config['MAIL_USERNAME']
        sender_email = app.config['MAIL_DEFAULT_SENDER']
        password = app.config['MAIL_PASSWORD']

        # Create a multipart message and set headers
        message = MIMEMultipart()
        message["From"] = "IOL Invoice" + '<' + sender_email + '>'
        message["To"] = user.email
        message["Subject"] = subject
        #message["Bcc"] = receiver_email  # Recommended for mass emails

        # Add body to email
        message.attach(MIMEText(body, "html"))

        text = message.as_string()

        #use outlook with port
        """sessionsmtp = smtplib.SMTP('smtp.office365.com', 587)
        sessionsmtp.ehlo()
        #enable security
        sessionsmtp.starttls()

        #login with mail_id and password
        sessionsmtp.login(email_username, password)

        text = message.as_string()
        sessionsmtp.sendmail(sender_email, user.email, text)
        sessionsmtp.quit()"""

        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(email_username, password)
        server.sendmail(sender_email, user.email, message.as_string())
        server.quit()

        flash("A confirmation email has been sent via email.", "success")
        return render_template('login.html', sitekey=sitekey )
        #flash("Account Created")
        #return redirect(url_for('login'))

    # else error check what the problem is
    elif u_unique == -1:
        flash("Email address already in use.")
        return render_template('register.html')

    elif u_unique == -2:
        flash("Username already in use.")
        return render_template('register.html')

    else:
        flash("Username and Email already in use.")
        return render_template('register.html')
    
    
@app.route('/confirm/<token>')
def confirm_email(token):
    sitekey = app.config['RECAPTCHA_SITE_KEY']
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'warning')
        
    user = User.query.filter_by(email=email).first()
    #print("error in confirm")
    if user.confirmed:
        flash('Account already confirmed. Please login.', 'success')
        
    else:
        user.confirmed = True
        user.confirmed_on = datetime.datetime.now()
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return render_template('login.html', sitekey=sitekey)
    
@app.route('/password-recovery/<token>')
def password_reset(token):
    sitekey = app.config['RECAPTCHA_SITE_KEY']
    try:
        email = confirm_token(token)
        username = request.args.get('username')
        return render_template('password-recovery.html', sitekey=sitekey, username=username)
    except:
        flash('The reset password link is invalid or has expired.', 'warning')
        
    
         
@app.route('/password-recover', methods=["GET", "POST"])
def password_recover():
    sitekey = app.config['RECAPTCHA_SITE_KEY']
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm-password']
        username = request.form['username']
        captcha_response = request.form['g-recaptcha-response']
    
    
        if not is_human(captcha_response):
            # Log invalid attempts
            status = "Sorry ! Please Check Im not a robot."
            flash(status, "warning")
            return render_template('password-recovery.html', sitekey=sitekey)
        # make sure the password match
        if confirm_password != password:
            flash("Passwords do not match", "warning")
            return render_template('password-recovery.html', sitekey=sitekey)
        
        # check if it meets the right complexity
        check_password = password_check(password)

         # generate error messages if it doesnt pass
        if True in check_password.values():
            for k,v in check_password.items():
                if str(v) == "True":
                    flash(k, "warning")

            return render_template('password-recovery.html', sitekey=sitekey)
       
        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        user = db.session.query(User).filter_by(username=username).first()
        user.password = pw_hash
        db.session.commit()
        
        return render_template('password-recovered.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_hashed = current_user.user_id_hash
    if request.method == 'POST':
        new_profile = ProfileData(user_hashed, request.form.get('businessname'), request.form.get('email'), request.form.get('ein'), request.form.get('address1'), request.form.get('address2'), request.form.get('city'), request.form.get('state'), request.form.get('zip'))
        db.session.add(new_profile)
        db.session.commit()
        #flash("Profile Adeed to Database")    
        return render_template('profile-added.html', user=current_user)
    return render_template('profile.html', user=current_user)

@app.route('/edit-profile')
@login_required

def edit_profile():
	user_hashed = current_user.user_id_hash
	try:
		found_profile_data = db.session.query(ProfileData).filter_by(user_id=(user_hashed)).first()
	except:
		render_template('404.html')
	
	return render_template('modify-profile.html', user=current_user, profile=found_profile_data)
	
@app.route('/show_profile', methods=['GET', 'PATCH', 'DELETE'])
@login_required
def show_profile():
	
	user_hashed=current_user.user_id_hash
	try:
		found_profile_data = db.session.query(ProfileData).filter_by(user_id=(user_hashed)).first()
	except:
		render_template('404.html')
	
	if request.method == b"PATCH":
		found_profile_data.user_id = user_hashed
		found_profile_data.businessname = request.form['businessname']
		found_profile_data.email = request.form['email']
		found_profile_data.ein = request.form['ein']
		found_profile_data.address1 = request.form['address1']
		found_profile_data.address2 = request.form['address2']
		found_profile_data.city = request.form['city']
		found_profile_data.state = request.form['state']
		found_profile_data.zip = request.form['zip']
		
		db.session.add(found_profile_data)
		db.session.commit()
		return render_template('profile-modified.html', user=current_user)
	
	if request.method == b"DELETE":
		db.session.delete(found_profile_data)
		db.session.commit()
		return render_template('profile-deleted.html', user=current_user)
	
	
	return render_template('show-profile.html', user=current_user, profile=found_profile_data)

@app.route('/invoice', methods=['GET', 'POST'])
@login_required
def invoice():
    
    user_hashed=current_user.user_id_hash
    sum = 0
    list_sum = []
    formated_float = 0.00
    counter = 0
   
    
    
    try:
        if request.method == 'POST':
            invoice_date=request.form['invoice_date']
            #print(invoice_date)
            date_inv=invoice_date.replace("-",",")
            y, m, d = date_inv.split(',')
            date_inv = date(int(y), int(m), int(d))
            
            #print(date_inv)
            new_invoice_data = InvoiceData(user_hashed, request.form['invoice_number'], request.form['businessname'], request.form['email'], request.form['ein'], request.form['address'], request.form['address2'], request.form['city'], request.form['state'], request.form['zip'], request.form['checker'], request.form['businessname_shipping'], request.form['email_shipping'], request.form['ein_shipping'],request.form['address_shipping'], request.form['address2_shipping'], request.form['city_shipping'], request.form['state_shipping'], request.form['zip_shipping'], date_inv, request.form['taxes'])
            db.session.add(new_invoice_data)
            db.session.commit()
            
            for desc, price, quant, amount in zip(request.form.getlist('item_desc[]'), request.form.getlist('item_price[]'), request.form.getlist('item_quant[]'), request.form.getlist('amount[]')):
                new_item = InvoiceItems(user_hashed, request.form['invoice_number'], desc, price, quant, amount)
                db.session.add(new_item)
                db.session.commit()
            new_invoice_values = InvoiceValues(user_hashed, request.form['invoice_number'], request.form['subtotal'], request.form['totaltax'], request.form['grandtotal'])
            db.session.add(new_invoice_values)
            db.session.commit()
            #return 'Invoice added to database
            found_user_data = db.session.query(User).filter_by(user_id_hash=(user_hashed)).all()
            found_invoice_data = db.session.query(InvoiceData).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).first()
            found_invoice_items = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).all()
            found_invoice_values = db.session.query(InvoiceValues).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).first() 
            found_profile_data = db.session.query(ProfileData).filter_by(user_id=(user_hashed)).first() 
            found_image_data = db.session.query(ImageData).filter_by(user_id=(user_hashed)).first() 
            found_invoice_items_rows = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).count()
            
            name=current_user.user_id_hash
            name=name.replace("/","$$$")
            name=name.replace(".","$$$")
            destination=name+"orig"+".png"
            qrcodepath = os.path.join(app.config['UPLOAD_FOLDER'], destination)
            print('qrcodepath: ', qrcodepath)
            qrcode_string = found_profile_data.businessname + '\n' + 'EIN: ' + found_profile_data.ein
            chars = QRCode(qrcode_string)
            chars.png(qrcodepath, scale=8)
            
            image = PIL.Image.open(os.path.join(app.config['UPLOAD_FOLDER'], destination))
            
            width, height = image.size
            
            #print(width, height)
            finalimagename=name+"qrcode.png" 
            basewidth = 150
            if width > 150:
                img = Image.open(os.path.join(app.config['UPLOAD_FOLDER'], destination))
                wpercent = (basewidth / float(img.size[0]))
                hsize = int((float(img.size[1]) * float(wpercent)))
                img = img.resize((basewidth, hsize), Image.ANTIALIAS)
                img.save(os.path.join(app.config['UPLOAD_FOLDER'], finalimagename))
                new__image = PIL.Image.open(os.path.join(app.config['UPLOAD_FOLDER'], finalimagename))
                width, height = new__image.size
               
            
            name_url_final="https://iol-accountant.onrender.com" + "/static/uploads" + "/" + finalimagename
            
            print(name_url_final)  


        

            #print(url_link)
            os.chdir(r"..")
            
            
            user_hashed=current_user.user_id_hash
            
            found_qrcode_data = db.session.query(QRcodeData).filter_by(user_id=(user_hashed)).all()
            for row in found_qrcode_data:
                QRcodeData.query.delete()
                db.session.commit()
            
            new_image = QRcodeData(user_hashed, finalimagename, name_url_final, width, height)
            db.session.add(new_image)
            db.session.commit()
            
            found_qrcode_data = db.session.query(QRcodeData).filter_by(user_id=(user_hashed)).first()
            
            
               
            POST_PER_PAGE = 7
            page = 1
            query = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).paginate(page=page, per_page=POST_PER_PAGE)
            
            name=user_hashed
            name=name.replace("/","$$$")
            name=name.replace(".","$$$") 
            #write html and pdf code
            print(app.config['UPLOAD_FOLDER'])
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","w")
            f.write("<html><head> \
            </head> \
            <body style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <tr> \
            <td style='vertical-align: top;' width='50%'> \
            <img src='https:" + found_image_data.image_url + "' alt='Logo'> \
            </td> \
            <td style='vertical-align: top; text-align:right;' width='50%'> \
            <span style='text-align:right;'>" + found_profile_data.businessname + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.email + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.ein + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.address1 + "</span><br />")
            f.close()
            if found_profile_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
                f.write("<span>" + found_profile_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html", "a")
            f.write("<span style='text-align:right;'>" + found_profile_data.city + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.state + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.zip + "</span> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
            <tr> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Billing Address</strong></td></tr></table> \
            </td> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Shipping Address</strong></td></tr></table> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <tr> \
            <td style='vertical-align: top;' width='50%' style='text-align:left;'> \
            <span style='text-align:left;'>" + found_invoice_data.businessname + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.email + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.ein + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.address + "</span><br />")
            f.close()
            if found_invoice_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
                f.write("<span style='text-align:left;'>" + found_invoice_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html", "a")
            f.write("<span style='text-align:left;'>" + found_invoice_data.city + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.state + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.zip + "</span> \
            </td> \
            <td style='vertical-align: top; text-align:left;' width='50%'> \
            <span style='text-align:left;'>" + found_invoice_data.businessname_shipping + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.email_shipping + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.ein_shipping + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.address_shipping + "</span><br />")
            f.close()
            if found_invoice_data.address2_shipping != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
                f.write("<span style='text-align:left;'>" + found_invoice_data.address2_shipping + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html", "a")
            f.write("<span style='text-align:left;'>" + found_invoice_data.city_shipping + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.state_shipping + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.zip_shipping + "</span> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 33%'><strong>Invoice Date:</strong>&nbsp;" + str(found_invoice_data.invoice_date) +"</td><td style='width: 33%'><strong>Invoice Number</strong>&nbsp;" + found_invoice_data.invoice_number + "</td><td style='width: 33%'><strong>Taxes</strong>&nbsp;" + found_invoice_data.taxes + "</td></tr>\
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
            f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            for item in found_invoice_items:
                f.write("<tr><td style='width: 25%;'><p><strong>Description</strong></p><p>" + item.item_desc +"</p></td><td style='width: 25%;'><p><strong>Price</strong></p><p>" + format_currency(str(item.item_price), 'USD', locale='en_US') + "</p></td><td style='width: 25%;'><p><strong>Quantity</strong></p><p>" + str(item.item_quant) + "</p></td><td style='width: 25%;'><p><strong>Total</strong></p><p>" + format_currency(str(item.amount), 'USD', locale='en_US') + "</p></td></tr>")
            f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("</table>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width:[] 50%'>" + format_currency(str(found_invoice_values.subtotal), 'USD', locale='en_US') + "</td></tr>")
            f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.taxes), 'USD', locale='en_US') + "</td></tr>")
            f.write("<tr><td style='width: 50%'><strong>Total</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.total), 'USD', locale='en_US') + "</td></tr>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("</table></td></tr></table>")
            f.close()            
            
            found_html_template_data = db.session.query(TemplateHTMLData).filter_by(user_id=(user_hashed)).all()
            for row in found_html_template_data:
                
                TemplateHTMLData.query.delete()
                db.session.commit()
            
            
            file_from = app.config['UPLOAD_FOLDER'] + "/email" + name + ".html" # This is name of the file to be uploaded
            
            print(file_from)
            
            
            email_url_final = "https://iol-accountant.onrender.com" + "/static/uploads/" + "uploads/" + "email" + name + ".html"
            print(email_url_final)
            
            new_template = TemplateHTMLData(found_invoice_data.email, user_hashed, email_url_final)
            db.session.add(new_template)
            db.session.commit()           
            found_html_template_data = db.session.query(TemplateHTMLData).filter_by(user_id=(user_hashed)).first()
                        
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","w")
            f.write("<html><head> \
            <style> \
            @page { \
            size: a4 portrait; \
            @frame header_frame {           /* Static frame */ \
            -pdf-frame-content: header_content; \
            left: 50pt; width: 512pt; top: 20pt; height: 170pt; \
            } \
            @frame content_frame {          /* Content Frame */ \
            left: 50pt; width: 512pt; top: 150pt; height: 632pt; \
            } \
            @frame footer_frame {           /* Another static Frame */ \
            -pdf-frame-content: footer_content; \
            left: 50pt; width: 512pt; top: 780pt; height: 20pt; \
            } \
            } \
            </style> \
            </head> \
            <body style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;' id='header_content'> \
            <tr> \
            <td style='vertical-align: top;' width='50%'> \
            <img src='https:" + found_image_data.image_url + "' alt='Logo'> \
            </td> \
            <td style='vertical-align: top; text-align:right;' width='50%'> \
            <span style='text-align:right;'>" + found_profile_data.businessname + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.email + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.ein + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.address1 + "</span><br />")
            f.close()
            if found_profile_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<span>" + found_profile_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html", "a")
            f.write("<span style='text-align:right;'>" + found_profile_data.city + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.state + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.zip + "</span> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
            <tr> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Billing Address</strong></td></tr></table> \
            </td> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Shipping Address</strong></td></tr></table> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
            <tr> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname + "</span><br /> \
            <span>" + found_invoice_data.email + "</span><br /> \
            <span>" + found_invoice_data.ein + "</span><br /> \
            <span>" + found_invoice_data.address + "</span><br />")
            f.close()
            if found_invoice_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<span>" + found_invoice_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html", "a")
            f.write("<span>" + found_invoice_data.city + "</span>&nbsp;<span>" + found_invoice_data.state + "&nbsp;</span>&nbsp;<span>" + found_invoice_data.zip +"</span> \
            </td></tr></table> \
            </td> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname_shipping + "</span><br /> \
            <span>" + found_invoice_data.email_shipping + "</span><br /> \
            <span>" + found_invoice_data.ein_shipping + "</span><br /> \
            <span>" + found_invoice_data.address_shipping + "</span><br />")
            f.close()
            if found_invoice_data.address2_shipping != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<span>" + found_invoice_data.address2_shipping + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
            f.write("<span>" + found_invoice_data.city_shipping + "</span>&nbsp;<span>" + found_invoice_data.state_shipping + "</span>&nbsp;<span>" + found_invoice_data.zip_shipping + "</span> \
            </td></tr></table> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 33%'><strong>Invoice Date:</strong>&nbsp;" + str(found_invoice_data.invoice_date) +"</td><td style='width: 33%'><strong>Invoice Number</strong>&nbsp;" + found_invoice_data.invoice_number + "</td><td style='width: 33%'><strong>Taxes</strong>&nbsp;" + found_invoice_data.taxes + "</td></tr>\
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
            
            for item in query.items:
                f.write("<tr><td style='width: 25%'><span><strong>Description</strong><br />" + item.item_desc +"</span></td><td style='width: 25%'><span><strong>Price</strong><br />" + format_currency(str(item.item_price), 'USD', locale='en_US') + "</span></td><td style='width: 25%'><span><strong>Quantity</strong><br />" + str(item.item_quant) + "</span></td><td style='width: 25%'><span><strong>Total</strong><br />" + format_currency(str(item.amount), 'USD', locale='en_US') + "</span></td></tr>")
                sum += float(item.amount)
                
                list_sum.append(sum)
                counter += 1
            f.write("</table>")                
            res_max = max(list_sum)
            print(res_max)
            print(len(list_sum))
            print(counter)
            print(found_invoice_items_rows)
            print(type(found_invoice_items_rows))
            f.close()
            
            if found_invoice_items_rows > POST_PER_PAGE:
                
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                
                f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
                 <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> ")
                f.close()
                list_number = len(list_sum) - 1
                taxes = float(found_invoice_data.taxes)
                subtotal = round(float(list_sum[list_number]), 2)
                taxes = round(float(list_sum[list_number] * float(taxes/100)), 2)
                amount = round(float(subtotal + taxes), 2)
                print(subtotal)
                
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width: 50%'>" + format_currency(str(subtotal), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(taxes), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Total</strong></td>")
                f.write("<td style='width: 50%'>" + format_currency(str(amount), 'USD', locale='en_US') + "</td></tr>")
                f.write("</table></table>")
                f.close()
                
                while(counter <= found_invoice_items_rows):
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<div><pdf:nextpage></div>")
                    f.close()        
                    page = query.next_num
                    query = query.next(error_out=False)
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%'> \
                <tr> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Billing Address</strong></td></tr></table> \
                </td> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Shipping Address</strong></td></tr></table> \
                </td> \
                </tr> \
                </table> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
                <tr> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname + "</span><br /> \
                <span>" + found_invoice_data.email + "</span><br /> \
                <span>" + found_invoice_data.ein + "</span><br /> \
                <span>" + found_invoice_data.address + "</span><br />")
                    f.close()
                    if found_invoice_data.address2 != '':
                        f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                        f.write("<span>" + found_invoice_data.address2 + "</span><br />")
                        f.close()
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html", "a")
                    f.write("<span>" + found_invoice_data.city + "</span>&nbsp;<span>" + found_invoice_data.state + "&nbsp;</span>&nbsp;<span>" + found_invoice_data.zip +"</span> \
                </td></tr></table> \
                </td> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname_shipping + "</span><br /> \
                <span>" + found_invoice_data.email_shipping + "</span><br /> \
                <span>" + found_invoice_data.ein_shipping + "</span><br /> \
                <span>" + found_invoice_data.address_shipping + "</span><br />")
                    f.close()
                    if found_invoice_data.address2_shipping != '':
                        f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                        f.write("<span>" + found_invoice_data.address2_shipping + "</span><br />")
                        f.close()
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<span>" + found_invoice_data.city_shipping + "</span>&nbsp;<span>" + found_invoice_data.state_shipping + "</span>&nbsp;<span>" + found_invoice_data.zip_shipping + "</span> \
                </td></tr></table> \
                </td> \
                </tr> \
                </table> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
                <tr><td style='width: 33%'><strong>Invoice Date:</strong>&nbsp;" + str(found_invoice_data.invoice_date) +"</td><td style='width: 33%'><strong>Invoice Number</strong>&nbsp;" + found_invoice_data.invoice_number + "</td><td style='width: 33%'><strong>Taxes</strong>&nbsp;" + found_invoice_data.taxes + "</td></tr>\
                </table>")
                    f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
                    f.close()
                
               
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    for item in query.items:
                    
                        f.write("<tr><td style='width: 25%'><span><strong>Description</strong><br />" + item.item_desc +"</span></td><td style='width: 25%'><span><strong>Price</strong><br />" + format_currency(str(item.item_price), 'USD', locale='en_US') + "</span></td><td style='width: 25%'><span><strong>Quantity</strong><br />" + str(item.item_quant) + "</span></td><td style='width: 25%'><span><strong>Total</strong><br />" + format_currency(str(item.amount), 'USD', locale='en_US') + "</span></td></tr>")
                        sum += item.amount
                        list_sum.append(sum)
                        counter += 1
                    f.write("</table>")
                    f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
                    f.close()
                    list_number = len(list_sum) - 1
                    taxes = float(found_invoice_data.taxes)
                    subtotal = round(float(list_sum[list_number]), 2)
                    taxes = round(float(list_sum[list_number] * float(taxes/100)), 2)
                    amount = round(float(subtotal + taxes), 2)
                    print(subtotal)
                
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width: 50%'>" + format_currency(str(subtotal), 'USD', locale='en_US') + "</td></tr>")
                    f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(taxes), 'USD', locale='en_US') + "</td></tr>")
                    f.write("<tr><td style='width: 50%'><strong>Total</strong></td>")
                    f.write("<td style='width: 50%'>" + format_currency(str(amount), 'USD', locale='en_US') + "</td></tr>")
                    f.close()
            
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("</table></table>")
                    f.close()
                    counter += 1
            else:
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("</table>")
                f.close()
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
                f.close()
            
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.subtotal), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.taxes), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Total</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.total), 'USD', locale='en_US') + "</td></tr>")
                f.close()
            
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("</table></table>")
                f.close() 
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
            f.write("<div id='footer_content' style='text-align: center;'>page <pdf:pagenumber> \
            of <pdf:pagecount> \
            </div> \
            </body> \
            </html>")
            
            
            f.close()
            
            OUTPUT_FILENAME = app.config['UPLOAD_FOLDER'] + "/" + name + ".pdf"
            TEMPLATE_FILE = app.config['UPLOAD_FOLDER'] + "/" + name + ".html"
            
            # Methods section ....
            def html_to_pdf(content, output):
            
                # Open file to write
                result_file = open(output, "w+b") # w+b to write in binary mode.

                # convert HTML to PDF
                pisa_status = pisa.CreatePDF(
                content,                   # the HTML to convert
                dest=result_file           # file handle to recieve result
                )           

                # close output file
                result_file.close()

                result = pisa_status.err

                if not result:
                    print("Successfully created PDF")
                else:
                    print("Error: unable to create the PDF")    

                # return False on success and True on errors
                return result



            def from_template(template, output):
   
                # Reading our template
                source_html = open(template, "r")
                content = source_html.read() # the HTML to convert
                source_html.close() # close template file

                html_to_pdf(content, output)
    
            from_template(TEMPLATE_FILE, OUTPUT_FILENAME)
            
            name=user_hashed
            name=name.replace("/","$$$")
            name=name.replace(".","$$$") 
                  
            pdf_final_url = "https://iol-accountant.onrender.com" + "/static/uploads" + "/" + name + ".pdf"
            print(pdf_final_url)
            
            new_template = TemplateData(found_invoice_data.email, user_hashed, pdf_final_url)
            db.session.add(new_template)
            db.session.commit()        
            found_template_data = db.session.query(TemplateData).filter_by(user_id=(user_hashed)).first()
            
            return render_template('invoice-html.html', user=current_user, invoice_data=found_invoice_data, items_data=found_invoice_items, invoice_values=found_invoice_values, profile_data=found_profile_data, image_data=found_image_data, template_data=found_template_data, qrcode_data=found_qrcode_data)   
               
        
        else:
            return render_template('invoice.html', user=current_user)
    except Exception as e:
        print(str(e))
        
    #return render_template('invoice.html')
    return 'Done'
    
@app.route('/invoiceedit', methods=['GET', 'POST'])
@login_required
def invoiceedit():
    
    user_hashed=current_user.user_id_hash
    sum = 0
    list_sum = []
    formated_float = 0.00
    counter = 0
   
    
    
    try:
        if request.method == 'POST':
            invoice_date=request.form['invoice_date']
            #print(invoice_date)
            date_inv=invoice_date.replace("-",",")
            y, m, d = date_inv.split(',')
            date_inv = date(int(y), int(m), int(d))
            
            #delete initial invoice
            
            invoice_number=request.form['invoice_number']
            
            
            found_invoice_data = db.session.query(InvoiceData).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).first()
            found_invoice_items = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).all()
            found_invoice_values = db.session.query(InvoiceValues).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).first() 
            
            db.session.delete(found_invoice_data)
            db.session.commit()
            
            for item in found_invoice_items:
                db.session.delete(item)
                db.session.commit()
            
            db.session.delete(found_invoice_values)
            db.session.commit()
            
            
            
            #print(date_inv)
            new_invoice_data = InvoiceData(user_hashed, request.form['invoice_number'], request.form['businessname'], request.form['email'], request.form['ein'], request.form['address'], request.form['address2'], request.form['city'], request.form['state'], request.form['zip'], request.form['checker'], request.form['businessname_shipping'], request.form['email_shipping'], request.form['ein_shipping'],request.form['address_shipping'], request.form['address2_shipping'], request.form['city_shipping'], request.form['state_shipping'], request.form['zip_shipping'], date_inv, request.form['taxes'])
            db.session.add(new_invoice_data)
            db.session.commit()
            
            for desc, price, quant, amount in zip(request.form.getlist('item_desc[]'), request.form.getlist('item_price[]'), request.form.getlist('item_quant[]'), request.form.getlist('amount[]')):
                new_item = InvoiceItems(user_hashed, request.form['invoice_number'], desc, price, quant, amount)
                db.session.add(new_item)
                db.session.commit()
            new_invoice_values = InvoiceValues(user_hashed, request.form['invoice_number'], request.form['subtotal'], request.form['totaltax'], request.form['grandtotal'])
            db.session.add(new_invoice_values)
            db.session.commit()
            #return 'Invoice added to database
            found_user_data = db.session.query(User).filter_by(user_id_hash=(user_hashed)).all()
            found_invoice_data = db.session.query(InvoiceData).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).first()
            found_invoice_items = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).all()
            found_invoice_values = db.session.query(InvoiceValues).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).first() 
            found_profile_data = db.session.query(ProfileData).filter_by(user_id=(user_hashed)).first() 
            found_image_data = db.session.query(ImageData).filter_by(user_id=(user_hashed)).first() 
            found_invoice_items_rows = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).count()
            
            name=current_user.user_id_hash
            name=name.replace("/","$$$")
            name=name.replace(".","$$$")
            destination=name+"orig"+".png"
            qrcodepath = os.path.join(app.config['UPLOAD_FOLDER'], destination)
            print('qrcodepath: ', qrcodepath)
            qrcode_string = found_profile_data.businessname + '\n' + 'EIN: ' + found_profile_data.ein
            chars = QRCode(qrcode_string)
            chars.png(qrcodepath, scale=8)
            
            image = PIL.Image.open(os.path.join(app.config['UPLOAD_FOLDER'], destination))
            
            width, height = image.size
            
            #print(width, height)
            finalimagename=name+"qrcode.png" 
            basewidth = 150
            if width > 150:
                img = Image.open(os.path.join(app.config['UPLOAD_FOLDER'], destination))
                wpercent = (basewidth / float(img.size[0]))
                hsize = int((float(img.size[1]) * float(wpercent)))
                img = img.resize((basewidth, hsize), Image.ANTIALIAS)
                img.save(os.path.join(app.config['UPLOAD_FOLDER'], finalimagename))
                new__image = PIL.Image.open(os.path.join(app.config['UPLOAD_FOLDER'], finalimagename))
                width, height = new__image.size
                
            upload_path = "static/uploads"
            os.chdir(upload_path)
            os.remove(destination)
            
            access_token = app.config['DROPBOX_ACCESS_TOKEN']
            transferData = TransferData(access_token)
            
            file_from = finalimagename
            file_to = '/iolcloud/' + finalimagename # The full path to upload the file to, including the file name
            dbx = dropbox.Dropbox(access_token)
            
              # API v2
            #transferData.upload_file(file_from, file_to)
            
            try:
                dbx.files_delete_v2("/iolcloud/" + finalimagename)
                transferData.upload_file(file_from, file_to)
            except:
                transferData.upload_file(file_from, file_to)
    
            #result = dbx.files_get_temporary_link(file_to)
            #dbx.sharing_create_shared_link(path = file_to, short_url=False, pending_upload=None)
            result = dbx.sharing_create_shared_link(path = file_to, short_url=False, pending_upload=None).url
           
            name_url=result.replace("https:","")
            name_url_final=name_url.replace("?dl=0","?raw=1")
            print(result)
            print(name_url)  


        

            #print(url_link)
            os.chdir(r"..")
            
            
            user_hashed=current_user.user_id_hash
            
            found_qrcode_data = db.session.query(QRcodeData).filter_by(user_id=(user_hashed)).all()
            for row in found_qrcode_data:
                QRcodeData.query.delete()
                db.session.commit()
            
            new_image = QRcodeData(user_hashed, finalimagename, name_url_final, width, height)
            db.session.add(new_image)
            db.session.commit()
            
            found_qrcode_data = db.session.query(QRcodeData).filter_by(user_id=(user_hashed)).first()
            
            
               
            POST_PER_PAGE = 7
            page = 1
            query = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).paginate(page=page, per_page=POST_PER_PAGE)
            
            name=user_hashed
            name=name.replace("/","$$$")
            name=name.replace(".","$$$") 
            #write html and pdf code
            print(app.config['UPLOAD_FOLDER'])
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","w")
            f.write("<html><head> \
            </head> \
            <body style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <tr> \
            <td style='vertical-align: top;' width='50%'> \
            <img src='https:" + found_image_data.image_url + "' alt='Logo'> \
            </td> \
            <td style='vertical-align: top; text-align:right;' width='50%'> \
            <span style='text-align:right;'>" + found_profile_data.businessname + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.email + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.ein + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.address1 + "</span><br />")
            f.close()
            if found_profile_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
                f.write("<span>" + found_profile_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html", "a")
            f.write("<span style='text-align:right;'>" + found_profile_data.city + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.state + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.zip + "</span> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
            <tr> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Billing Address</strong></td></tr></table> \
            </td> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Shipping Address</strong></td></tr></table> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <tr> \
            <td style='vertical-align: top;' width='50%' style='text-align:left;'> \
            <span style='text-align:left;'>" + found_invoice_data.businessname + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.email + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.ein + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.address + "</span><br />")
            f.close()
            if found_invoice_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
                f.write("<span style='text-align:left;'>" + found_invoice_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html", "a")
            f.write("<span style='text-align:left;'>" + found_invoice_data.city + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.state + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.zip + "</span> \
            </td> \
            <td style='vertical-align: top; text-align:left;' width='50%'> \
            <span style='text-align:left;'>" + found_invoice_data.businessname_shipping + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.email_shipping + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.ein_shipping + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.address_shipping + "</span><br />")
            f.close()
            if found_invoice_data.address2_shipping != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
                f.write("<span style='text-align:left;'>" + found_invoice_data.address2_shipping + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html", "a")
            f.write("<span style='text-align:left;'>" + found_invoice_data.city_shipping + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.state_shipping + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.zip_shipping + "</span> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 33%'><strong>Invoice Date:</strong>&nbsp;" + str(found_invoice_data.invoice_date) +"</td><td style='width: 33%'><strong>Invoice Number</strong>&nbsp;" + found_invoice_data.invoice_number + "</td><td style='width: 33%'><strong>Taxes</strong>&nbsp;" + found_invoice_data.taxes + "</td></tr>\
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
            f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            for item in found_invoice_items:
                f.write("<tr><td style='width: 25%;'><p><strong>Description</strong></p><p>" + item.item_desc +"</p></td><td style='width: 25%;'><p><strong>Price</strong></p><p>" + format_currency(str(item.item_price), 'USD', locale='en_US') + "</p></td><td style='width: 25%;'><p><strong>Quantity</strong></p><p>" + str(item.item_quant) + "</p></td><td style='width: 25%;'><p><strong>Total</strong></p><p>" + format_currency(str(item.amount), 'USD', locale='en_US') + "</p></td></tr>")
            f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("</table>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width:[] 50%'>" + format_currency(str(found_invoice_values.subtotal), 'USD', locale='en_US') + "</td></tr>")
            f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.taxes), 'USD', locale='en_US') + "</td></tr>")
            f.write("<tr><td style='width: 50%'><strong>Total</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.total), 'USD', locale='en_US') + "</td></tr>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("</table></td></tr></table>")
            f.close()            
            
            access_token = app.config['DROPBOX_ACCESS_TOKEN']
            
            dbx = dropbox.Dropbox(access_token)
            found_html_template_data = db.session.query(TemplateHTMLData).filter_by(user_id=(user_hashed)).all()
            for row in found_html_template_data:
                
                TemplateHTMLData.query.delete()
                db.session.commit()
            
            
                
                
            transferData = TransferData(access_token)   
            file_from = app.config['UPLOAD_FOLDER'] + "/email" + name + ".html" # This is name of the file to be uploaded
            file_to = "/iolcloud/email" + name + ".html"  # This is the full path to upload the file to, including name that you wish the file to be called once uploaded.
            print(file_from)
            print(file_to)
            
            try:
                dbx.files_delete_v2("/iolcloud/email" + name + ".html")
                transferData.upload_file(file_from, file_to)
            except:
                transferData.upload_file(file_from, file_to)
                
                    
            
            result = dbx.files_get_temporary_link(file_to)
            print(result.link)
            
            new_template = TemplateHTMLData(found_invoice_data.email, user_hashed, result.link)
            db.session.add(new_template)
            db.session.commit()           
            found_html_template_data = db.session.query(TemplateHTMLData).filter_by(user_id=(user_hashed)).first()
                        
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","w")
            f.write("<html><head> \
            <style> \
            @page { \
            size: a4 portrait; \
            @frame header_frame {           /* Static frame */ \
            -pdf-frame-content: header_content; \
            left: 50pt; width: 512pt; top: 20pt; height: 170pt; \
            } \
            @frame content_frame {          /* Content Frame */ \
            left: 50pt; width: 512pt; top: 150pt; height: 632pt; \
            } \
           @frame footer_frame {           /* Another static Frame */ \
            -pdf-frame-content: footer_content; \
            left: 50pt; width: 512pt; top: 780pt; height: 20pt; \
            } \
            } \
            </style> \
            </head> \
            <body style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;' id='header_content'> \
            <tr> \
            <td style='vertical-align: top;' width='50%'> \
            <img src='https:" + found_image_data.image_url + "' alt='Logo'> \
            </td> \
            <td style='vertical-align: top; text-align:right;' width='50%'> \
            <span style='text-align:right;'>" + found_profile_data.businessname + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.email + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.ein + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.address1 + "</span><br />")
            f.close()
            if found_profile_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<span>" + found_profile_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html", "a")
            f.write("<span style='text-align:right;'>" + found_profile_data.city + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.state + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.zip + "</span> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
            <tr> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Billing Address</strong></td></tr></table> \
            </td> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Shipping Address</strong></td></tr></table> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
            <tr> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname + "</span><br /> \
            <span>" + found_invoice_data.email + "</span><br /> \
            <span>" + found_invoice_data.ein + "</span><br /> \
            <span>" + found_invoice_data.address + "</span><br />")
            f.close()
            if found_invoice_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<span>" + found_invoice_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html", "a")
            f.write("<span>" + found_invoice_data.city + "</span>&nbsp;<span>" + found_invoice_data.state + "&nbsp;</span>&nbsp;<span>" + found_invoice_data.zip +"</span> \
            </td></tr></table> \
            </td> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname_shipping + "</span><br /> \
            <span>" + found_invoice_data.email_shipping + "</span><br /> \
            <span>" + found_invoice_data.ein_shipping + "</span><br /> \
            <span>" + found_invoice_data.address_shipping + "</span><br />")
            f.close()
            if found_invoice_data.address2_shipping != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<span>" + found_invoice_data.address2_shipping + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
            f.write("<span>" + found_invoice_data.city_shipping + "</span>&nbsp;<span>" + found_invoice_data.state_shipping + "</span>&nbsp;<span>" + found_invoice_data.zip_shipping + "</span> \
            </td></tr></table> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 33%'><strong>Invoice Date:</strong>&nbsp;" + str(found_invoice_data.invoice_date) +"</td><td style='width: 33%'><strong>Invoice Number</strong>&nbsp;" + found_invoice_data.invoice_number + "</td><td style='width: 33%'><strong>Taxes</strong>&nbsp;" + found_invoice_data.taxes + "</td></tr>\
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
            
            for item in query.items:
                f.write("<tr><td style='width: 25%'><span><strong>Description</strong><br />" + item.item_desc +"</span></td><td style='width: 25%'><span><strong>Price</strong><br />" + format_currency(str(item.item_price), 'USD', locale='en_US') + "</span></td><td style='width: 25%'><span><strong>Quantity</strong><br />" + str(item.item_quant) + "</span></td><td style='width: 25%'><span><strong>Total</strong><br />" + format_currency(str(item.amount), 'USD', locale='en_US') + "</span></td></tr>")
                sum += item.amount
                
                list_sum.append(sum)
                counter += 1
            f.write("</table>")                
            res_max = max(list_sum)
            print(res_max)
            print(len(list_sum))
            print(counter)
            print(found_invoice_items_rows)
            print(type(found_invoice_items_rows))
            f.close()
            
            if found_invoice_items_rows > POST_PER_PAGE:
                
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                
                f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
                 <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> ")
                f.close()
                list_number = len(list_sum) - 1
                taxes = float(found_invoice_data.taxes)
                subtotal = round(float(list_sum[list_number]), 2)
                taxes = round(float(list_sum[list_number] * float(taxes/100)), 2)
                amount = round(float(subtotal + taxes), 2)
                print(subtotal)
                
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width: 50%'>" + format_currency(str(subtotal), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(taxes), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Total</strong></td>")
                f.write("<td style='width: 50%'>" + format_currency(str(amount), 'USD', locale='en_US') + "</td></tr>")
                f.write("</table></table>")
                f.close()
                
                while(counter <= found_invoice_items_rows):
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<div><pdf:nextpage></div>")
                    f.close()        
                    page = query.next_num
                    query = query.next(error_out=False)
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%'> \
                <tr> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Billing Address</strong></td></tr></table> \
                </td> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Shipping Address</strong></td></tr></table> \
                </td> \
                </tr> \
                </table> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
                <tr> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname + "</span><br /> \
                <span>" + found_invoice_data.email + "</span><br /> \
                <span>" + found_invoice_data.ein + "</span><br /> \
                <span>" + found_invoice_data.address + "</span><br />")
                    f.close()
                    if found_invoice_data.address2 != '':
                        f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                        f.write("<span>" + found_invoice_data.address2 + "</span><br />")
                        f.close()
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html", "a")
                    f.write("<span>" + found_invoice_data.city + "</span>&nbsp;<span>" + found_invoice_data.state + "&nbsp;</span>&nbsp;<span>" + found_invoice_data.zip +"</span> \
                </td></tr></table> \
                </td> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname_shipping + "</span><br /> \
                <span>" + found_invoice_data.email_shipping + "</span><br /> \
                <span>" + found_invoice_data.ein_shipping + "</span><br /> \
                <span>" + found_invoice_data.address_shipping + "</span><br />")
                    f.close()
                    if found_invoice_data.address2_shipping != '':
                        f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                        f.write("<span>" + found_invoice_data.address2_shipping + "</span><br />")
                        f.close()
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<span>" + found_invoice_data.city_shipping + "</span>&nbsp;<span>" + found_invoice_data.state_shipping + "</span>&nbsp;<span>" + found_invoice_data.zip_shipping + "</span> \
                </td></tr></table> \
                </td> \
                </tr> \
                </table> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
                <tr><td style='width: 33%'><strong>Invoice Date:</strong>&nbsp;" + str(found_invoice_data.invoice_date) +"</td><td style='width: 33%'><strong>Invoice Number</strong>&nbsp;" + found_invoice_data.invoice_number + "</td><td style='width: 33%'><strong>Taxes</strong>&nbsp;" + found_invoice_data.taxes + "</td></tr>\
                </table>")
                    f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
                    f.close()
                
               
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    for item in query.items:
                    
                        f.write("<tr><td style='width: 25%'><span><strong>Description</strong><br />" + item.item_desc +"</span></td><td style='width: 25%'><span><strong>Price</strong><br />" + format_currency(str(item.item_price), 'USD', locale='en_US') + "</span></td><td style='width: 25%'><span><strong>Quantity</strong><br />" + str(item.item_quant) + "</span></td><td style='width: 25%'><span><strong>Total</strong><br />" + format_currency(str(item.amount), 'USD', locale='en_US') + "</span></td></tr>")
                        sum += item.amount
                        list_sum.append(sum)
                        counter += 1
                    f.write("</table>")
                    f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
                    f.close()
                    list_number = len(list_sum) - 1
                    taxes = float(found_invoice_data.taxes)
                    subtotal = round(float(list_sum[list_number]), 2)
                    taxes = round(float(list_sum[list_number] * float(taxes/100)), 2)
                    amount = round(float(subtotal + taxes), 2)
                    print(subtotal)
                
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width: 50%'>" + format_currency(str(subtotal), 'USD', locale='en_US') + "</td></tr>")
                    f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(taxes), 'USD', locale='en_US') + "</td></tr>")
                    f.write("<tr><td style='width: 50%'><strong>Total</strong></td>")
                    f.write("<td style='width: 50%'>" + format_currency(str(amount), 'USD', locale='en_US') + "</td></tr>")
                    f.close()
            
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("</table></table>")
                    f.close()
                    counter += 1
            else:
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("</table>")
                f.close()
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
                f.close()
            
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.subtotal), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.taxes), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Total</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.total), 'USD', locale='en_US') + "</td></tr>")
                f.close()
            
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("</table></table>")
                f.close() 
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
            f.write("<div id='footer_content' style='text-align: center;'>page <pdf:pagenumber> \
            of <pdf:pagecount> \
            </div> \
            </body> \
            </html>")
            
            
            f.close()
            
            OUTPUT_FILENAME = app.config['UPLOAD_FOLDER'] + "/" + name + ".pdf"
            TEMPLATE_FILE = app.config['UPLOAD_FOLDER'] + "/" + name + ".html"
            
            # Methods section ....
            def html_to_pdf(content, output):
            
                # Open file to write
                result_file = open(output, "w+b") # w+b to write in binary mode.

                # convert HTML to PDF
                pisa_status = pisa.CreatePDF(
                content,                   # the HTML to convert
                dest=result_file           # file handle to recieve result
                )           

                # close output file
                result_file.close()

                result = pisa_status.err

                if not result:
                    print("Successfully created PDF")
                else:
                    print("Error: unable to create the PDF")    

                # return False on success and True on errors
                return result



            def from_template(template, output):
   
                # Reading our template
                source_html = open(template, "r")
                content = source_html.read() # the HTML to convert
                source_html.close() # close template file

                html_to_pdf(content, output)
    
            from_template(TEMPLATE_FILE, OUTPUT_FILENAME)
            
            name=user_hashed
            name=name.replace("/","$$$")
            name=name.replace(".","$$$") 
            
            #INPUT_FILENAME = app.config['UPLOAD_FOLDER'] + "/" + name + ".pdf"
            #OUTPUT_TEMPLATE = '/iolcloud/' + name + ".pdf"
            
            access_token = app.config['DROPBOX_ACCESS_TOKEN']
            
            dbx = dropbox.Dropbox(access_token)
            found_template_data = db.session.query(TemplateData).filter_by(user_id=(user_hashed)).all()
            for row in found_template_data:
                
                TemplateData.query.delete()
                db.session.commit()
            
            
                
                
            transferData = TransferData(access_token)   
            file_from = app.config['UPLOAD_FOLDER'] + "/" + name + ".pdf" # This is name of the file to be uploaded
            file_to = "/iolcloud/" + name + ".pdf"  # This is the full path to upload the file to, including name that you wish the file to be called once uploaded.
            print(file_from)
            print(file_to)
            
            try:
                dbx.files_delete_v2("/iolcloud/" + name + ".pdf")
                transferData.upload_file(file_from, file_to)
            except:
                transferData.upload_file(file_from, file_to)
                
                    
            
            result = dbx.files_get_temporary_link(file_to)
            print(result.link)
            
            new_template = TemplateData(found_invoice_data.email, user_hashed, result.link)
            db.session.add(new_template)
            db.session.commit()           
            found_template_data = db.session.query(TemplateData).filter_by(user_id=(user_hashed)).first()
            
            return render_template('invoice-html.html', user=current_user, invoice_data=found_invoice_data, items_data=found_invoice_items, invoice_values=found_invoice_values, profile_data=found_profile_data, image_data=found_image_data, template_data=found_template_data, qrcode_data=found_qrcode_data)   
               
        
        else:
            return render_template('invoice.html', user=current_user)
    except Exception as e:
        print(str(e))
        
    #return render_template('invoice.html')
    return 'Done'
    
    
@app.route('/invoicenumber', methods=['GET', 'POST'])
@login_required
def invoicenumber():
    
    user_hashed=current_user.user_id_hash
    sum = 0
    list_sum = []
    formated_float = 0.00
    counter = 0
   
    
    
    try:
        if request.method == 'POST':
            invoice_number=request.form['invoice_number']
            
            found_user_data = db.session.query(User).filter_by(user_id_hash=(user_hashed)).all()
            found_invoice_data = db.session.query(InvoiceData).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).first()
            found_invoice_items = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).all()
            found_invoice_values = db.session.query(InvoiceValues).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).first() 
            found_profile_data = db.session.query(ProfileData).filter_by(user_id=(user_hashed)).first() 
            found_image_data = db.session.query(ImageData).filter_by(user_id=(user_hashed)).first() 
            found_invoice_items_rows = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).count()
            
            name=current_user.user_id_hash
            name=name.replace("/","$$$")
            name=name.replace(".","$$$")
            destination=name+"orig"+".png"
            qrcodepath = os.path.join(app.config['UPLOAD_FOLDER'], destination)
            print('qrcodepath: ', qrcodepath)
            qrcode_string = found_profile_data.businessname + '\n' + 'EIN: ' + found_profile_data.ein
            chars = QRCode(qrcode_string)
            chars.png(qrcodepath, scale=8)
            
            image = PIL.Image.open(os.path.join(app.config['UPLOAD_FOLDER'], destination))
            
            width, height = image.size
            
            #print(width, height)
            finalimagename=name+"qrcode.png" 
            basewidth = 150
            if width > 150:
                img = Image.open(os.path.join(app.config['UPLOAD_FOLDER'], destination))
                wpercent = (basewidth / float(img.size[0]))
                hsize = int((float(img.size[1]) * float(wpercent)))
                img = img.resize((basewidth, hsize), Image.ANTIALIAS)
                img.save(os.path.join(app.config['UPLOAD_FOLDER'], finalimagename))
                new__image = PIL.Image.open(os.path.join(app.config['UPLOAD_FOLDER'], finalimagename))
                width, height = new__image.size
                
            upload_path = "static/uploads"
            os.chdir(upload_path)
            os.remove(destination)
            
            access_token = app.config['DROPBOX_ACCESS_TOKEN']
            transferData = TransferData(access_token)
            
            file_from = finalimagename
            file_to = '/iolcloud/' + finalimagename # The full path to upload the file to, including the file name
            dbx = dropbox.Dropbox(access_token)
            
              # API v2
            #transferData.upload_file(file_from, file_to)
            
            try:
                dbx.files_delete_v2("/iolcloud/" + finalimagename)
                transferData.upload_file(file_from, file_to)
            except:
                transferData.upload_file(file_from, file_to)
    
            #result = dbx.files_get_temporary_link(file_to)
            #dbx.sharing_create_shared_link(path = file_to, short_url=False, pending_upload=None)
            result = dbx.sharing_create_shared_link(path = file_to, short_url=False, pending_upload=None).url
           
            name_url=result.replace("https:","")
            name_url_final=name_url.replace("?dl=0","?raw=1")
            print(result)
            print(name_url)  


        

            #print(url_link)
            os.chdir(r"..")
            
            
            user_hashed=current_user.user_id_hash
            
            found_qrcode_data = db.session.query(QRcodeData).filter_by(user_id=(user_hashed)).all()
            for row in found_qrcode_data:
                QRcodeData.query.delete()
                db.session.commit()
            
            new_image = QRcodeData(user_hashed, finalimagename, name_url_final, width, height)
            db.session.add(new_image)
            db.session.commit()
            
            found_qrcode_data = db.session.query(QRcodeData).filter_by(user_id=(user_hashed)).first()
            
            
               
            POST_PER_PAGE = 7
            page = 1
            query = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).paginate(page=page, per_page=POST_PER_PAGE)
            
            name=user_hashed
            name=name.replace("/","$$$")
            name=name.replace(".","$$$") 
            #write html and pdf code
            print(app.config['UPLOAD_FOLDER'])
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","w")
            f.write("<html><head> \
            </head> \
            <body style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <tr> \
            <td style='vertical-align: top;' width='50%'> \
            <img src='https:" + found_image_data.image_url + "' alt='Logo'> \
            </td> \
            <td style='vertical-align: top; text-align:right;' width='50%'> \
            <span style='text-align:right;'>" + found_profile_data.businessname + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.email + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.ein + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.address1 + "</span><br />")
            f.close()
            if found_profile_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
                f.write("<span>" + found_profile_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html", "a")
            f.write("<span style='text-align:right;'>" + found_profile_data.city + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.state + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.zip + "</span> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
            <tr> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Billing Address</strong></td></tr></table> \
            </td> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Shipping Address</strong></td></tr></table> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <tr> \
            <td style='vertical-align: top;' width='50%' style='text-align:left;'> \
            <span style='text-align:left;'>" + found_invoice_data.businessname + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.email + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.ein + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.address + "</span><br />")
            f.close()
            if found_invoice_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
                f.write("<span style='text-align:left;'>" + found_invoice_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html", "a")
            f.write("<span style='text-align:left;'>" + found_invoice_data.city + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.state + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.zip + "</span> \
            </td> \
            <td style='vertical-align: top; text-align:left;' width='50%'> \
            <span style='text-align:left;'>" + found_invoice_data.businessname_shipping + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.email_shipping + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.ein_shipping + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.address_shipping + "</span><br />")
            f.close()
            if found_invoice_data.address2_shipping != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
                f.write("<span style='text-align:left;'>" + found_invoice_data.address2_shipping + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html", "a")
            f.write("<span style='text-align:left;'>" + found_invoice_data.city_shipping + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.state_shipping + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.zip_shipping + "</span> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 33%'><strong>Invoice Date:</strong>&nbsp;" + str(found_invoice_data.invoice_date) +"</td><td style='width: 33%'><strong>Invoice Number</strong>&nbsp;" + found_invoice_data.invoice_number + "</td><td style='width: 33%'><strong>Taxes</strong>&nbsp;" + found_invoice_data.taxes + "</td></tr>\
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
            f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            for item in found_invoice_items:
                f.write("<tr><td style='width: 25%;'><p><strong>Description</strong></p><p>" + item.item_desc +"</p></td><td style='width: 25%;'><p><strong>Price</strong></p><p>" + format_currency(str(item.item_price), 'USD', locale='en_US') + "</p></td><td style='width: 25%;'><p><strong>Quantity</strong></p><p>" + str(item.item_quant) + "</p></td><td style='width: 25%;'><p><strong>Total</strong></p><p>" + format_currency(str(item.amount), 'USD', locale='en_US') + "</p></td></tr>")
            f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("</table>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width:[] 50%'>" + format_currency(str(found_invoice_values.subtotal), 'USD', locale='en_US') + "</td></tr>")
            f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.taxes), 'USD', locale='en_US') + "</td></tr>")
            f.write("<tr><td style='width: 50%'><strong>Total</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.total), 'USD', locale='en_US') + "</td></tr>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("</table></td></tr></table>")
            f.close()            
            
            access_token = app.config['DROPBOX_ACCESS_TOKEN']
            
            dbx = dropbox.Dropbox(access_token)
            found_html_template_data = db.session.query(TemplateHTMLData).filter_by(user_id=(user_hashed)).all()
            for row in found_html_template_data:
                
                TemplateHTMLData.query.delete()
                db.session.commit()
            
            
                
                
            transferData = TransferData(access_token)   
            file_from = app.config['UPLOAD_FOLDER'] + "/email" + name + ".html" # This is name of the file to be uploaded
            file_to = "/iolcloud/email" + name + ".html"  # This is the full path to upload the file to, including name that you wish the file to be called once uploaded.
            print(file_from)
            print(file_to)
            
            try:
                dbx.files_delete_v2("/iolcloud/email" + name + ".html")
                transferData.upload_file(file_from, file_to)
            except:
                transferData.upload_file(file_from, file_to)
                
                    
            
            result = dbx.files_get_temporary_link(file_to)
            print(result.link)
            
            new_template = TemplateHTMLData(found_invoice_data.email, user_hashed, result.link)
            db.session.add(new_template)
            db.session.commit()           
            found_html_template_data = db.session.query(TemplateHTMLData).filter_by(user_id=(user_hashed)).first()
                        
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","w")
            f.write("<html><head> \
            <style> \
            @page { \
            size: a4 portrait; \
            @frame header_frame {           /* Static frame */ \
            -pdf-frame-content: header_content; \
            left: 50pt; width: 512pt; top: 20pt; height: 170pt; \
            } \
            @frame content_frame {          /* Content Frame */ \
            left: 50pt; width: 512pt; top: 150pt; height: 632pt; \
            } \
           @frame footer_frame {           /* Another static Frame */ \
            -pdf-frame-content: footer_content; \
            left: 50pt; width: 512pt; top: 780pt; height: 20pt; \
            } \
            } \
            </style> \
            </head> \
            <body style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;' id='header_content'> \
            <tr> \
            <td style='vertical-align: top;' width='50%'> \
            <img src='https:" + found_image_data.image_url + "' alt='Logo'> \
            </td> \
            <td style='vertical-align: top; text-align:right;' width='50%'> \
            <span style='text-align:right;'>" + found_profile_data.businessname + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.email + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.ein + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.address1 + "</span><br />")
            f.close()
            if found_profile_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<span>" + found_profile_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html", "a")
            f.write("<span style='text-align:right;'>" + found_profile_data.city + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.state + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.zip + "</span> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
            <tr> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Billing Address</strong></td></tr></table> \
            </td> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Shipping Address</strong></td></tr></table> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
            <tr> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname + "</span><br /> \
            <span>" + found_invoice_data.email + "</span><br /> \
            <span>" + found_invoice_data.ein + "</span><br /> \
            <span>" + found_invoice_data.address + "</span><br />")
            f.close()
            if found_invoice_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<span>" + found_invoice_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html", "a")
            f.write("<span>" + found_invoice_data.city + "</span>&nbsp;<span>" + found_invoice_data.state + "&nbsp;</span>&nbsp;<span>" + found_invoice_data.zip +"</span> \
            </td></tr></table> \
            </td> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname_shipping + "</span><br /> \
            <span>" + found_invoice_data.email_shipping + "</span><br /> \
            <span>" + found_invoice_data.ein_shipping + "</span><br /> \
            <span>" + found_invoice_data.address_shipping + "</span><br />")
            f.close()
            if found_invoice_data.address2_shipping != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<span>" + found_invoice_data.address2_shipping + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
            f.write("<span>" + found_invoice_data.city_shipping + "</span>&nbsp;<span>" + found_invoice_data.state_shipping + "</span>&nbsp;<span>" + found_invoice_data.zip_shipping + "</span> \
            </td></tr></table> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 33%'><strong>Invoice Date:</strong>&nbsp;" + str(found_invoice_data.invoice_date) +"</td><td style='width: 33%'><strong>Invoice Number</strong>&nbsp;" + found_invoice_data.invoice_number + "</td><td style='width: 33%'><strong>Taxes</strong>&nbsp;" + found_invoice_data.taxes + "</td></tr>\
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
            
            for item in query.items:
                f.write("<tr><td style='width: 25%'><span><strong>Description</strong><br />" + item.item_desc +"</span></td><td style='width: 25%'><span><strong>Price</strong><br />" + format_currency(str(item.item_price), 'USD', locale='en_US') + "</span></td><td style='width: 25%'><span><strong>Quantity</strong><br />" + str(item.item_quant) + "</span></td><td style='width: 25%'><span><strong>Total</strong><br />" + format_currency(str(item.amount), 'USD', locale='en_US') + "</span></td></tr>")
                sum += item.amount
                
                list_sum.append(sum)
                counter += 1
            f.write("</table>")                
            res_max = max(list_sum)
            print(res_max)
            print(len(list_sum))
            print(counter)
            print(found_invoice_items_rows)
            print(type(found_invoice_items_rows))
            f.close()
            
            if found_invoice_items_rows > POST_PER_PAGE:
                
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                
                f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
                 <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> ")
                f.close()
                list_number = len(list_sum) - 1
                taxes = float(found_invoice_data.taxes)
                subtotal = round(float(list_sum[list_number]), 2)
                taxes = round(float(list_sum[list_number] * float(taxes/100)), 2)
                amount = round(float(subtotal + taxes), 2)
                print(subtotal)
                
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width: 50%'>" + format_currency(str(subtotal), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(taxes), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Total</strong></td>")
                f.write("<td style='width: 50%'>" + format_currency(str(amount), 'USD', locale='en_US') + "</td></tr>")
                f.write("</table></table>")
                f.close()
                
                while(counter <= found_invoice_items_rows):
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<div><pdf:nextpage></div>")
                    f.close()        
                    page = query.next_num
                    query = query.next(error_out=False)
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%'> \
                <tr> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Billing Address</strong></td></tr></table> \
                </td> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Shipping Address</strong></td></tr></table> \
                </td> \
                </tr> \
                </table> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
                <tr> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname + "</span><br /> \
                <span>" + found_invoice_data.email + "</span><br /> \
                <span>" + found_invoice_data.ein + "</span><br /> \
                <span>" + found_invoice_data.address + "</span><br />")
                    f.close()
                    if found_invoice_data.address2 != '':
                        f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                        f.write("<span>" + found_invoice_data.address2 + "</span><br />")
                        f.close()
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html", "a")
                    f.write("<span>" + found_invoice_data.city + "</span>&nbsp;<span>" + found_invoice_data.state + "&nbsp;</span>&nbsp;<span>" + found_invoice_data.zip +"</span> \
                </td></tr></table> \
                </td> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname_shipping + "</span><br /> \
                <span>" + found_invoice_data.email_shipping + "</span><br /> \
                <span>" + found_invoice_data.ein_shipping + "</span><br /> \
                <span>" + found_invoice_data.address_shipping + "</span><br />")
                    f.close()
                    if found_invoice_data.address2_shipping != '':
                        f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                        f.write("<span>" + found_invoice_data.address2_shipping + "</span><br />")
                        f.close()
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<span>" + found_invoice_data.city_shipping + "</span>&nbsp;<span>" + found_invoice_data.state_shipping + "</span>&nbsp;<span>" + found_invoice_data.zip_shipping + "</span> \
                </td></tr></table> \
                </td> \
                </tr> \
                </table> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
                <tr><td style='width: 33%'><strong>Invoice Date:</strong>&nbsp;" + str(found_invoice_data.invoice_date) +"</td><td style='width: 33%'><strong>Invoice Number</strong>&nbsp;" + found_invoice_data.invoice_number + "</td><td style='width: 33%'><strong>Taxes</strong>&nbsp;" + found_invoice_data.taxes + "</td></tr>\
                </table>")
                    f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
                    f.close()
                
               
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    for item in query.items:
                    
                        f.write("<tr><td style='width: 25%'><span><strong>Description</strong><br />" + item.item_desc +"</span></td><td style='width: 25%'><span><strong>Price</strong><br />" + format_currency(str(item.item_price), 'USD', locale='en_US') + "</span></td><td style='width: 25%'><span><strong>Quantity</strong><br />" + str(item.item_quant) + "</span></td><td style='width: 25%'><span><strong>Total</strong><br />" + format_currency(str(item.amount), 'USD', locale='en_US') + "</span></td></tr>")
                        sum += item.amount
                        list_sum.append(sum)
                        counter += 1
                    f.write("</table>")
                    f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
                    f.close()
                    list_number = len(list_sum) - 1
                    taxes = float(found_invoice_data.taxes)
                    subtotal = round(float(list_sum[list_number]), 2)
                    taxes = round(float(list_sum[list_number] * float(taxes/100)), 2)
                    amount = round(float(subtotal + taxes), 2)
                    print(subtotal)
                
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width: 50%'>" + format_currency(str(subtotal), 'USD', locale='en_US') + "</td></tr>")
                    f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(taxes), 'USD', locale='en_US') + "</td></tr>")
                    f.write("<tr><td style='width: 50%'><strong>Total</strong></td>")
                    f.write("<td style='width: 50%'>" + format_currency(str(amount), 'USD', locale='en_US') + "</td></tr>")
                    f.close()
            
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("</table></table>")
                    f.close()
                    counter += 1
            else:
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("</table>")
                f.close()
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
                f.close()
            
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.subtotal), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.taxes), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Total</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.total), 'USD', locale='en_US') + "</td></tr>")
                f.close()
            
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("</table></table>")
                f.close() 
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
            f.write("<div id='footer_content' style='text-align: center;'>page <pdf:pagenumber> \
            of <pdf:pagecount> \
            </div> \
            </body> \
            </html>")
            
            
            f.close()
            
            OUTPUT_FILENAME = app.config['UPLOAD_FOLDER'] + "/" + name + ".pdf"
            TEMPLATE_FILE = app.config['UPLOAD_FOLDER'] + "/" + name + ".html"
            
            # Methods section ....
            def html_to_pdf(content, output):
            
                # Open file to write
                result_file = open(output, "w+b") # w+b to write in binary mode.

                # convert HTML to PDF
                pisa_status = pisa.CreatePDF(
                content,                   # the HTML to convert
                dest=result_file           # file handle to recieve result
                )           

                # close output file
                result_file.close()

                result = pisa_status.err

                if not result:
                    print("Successfully created PDF")
                else:
                    print("Error: unable to create the PDF")    

                # return False on success and True on errors
                return result



            def from_template(template, output):
   
                # Reading our template
                source_html = open(template, "r")
                content = source_html.read() # the HTML to convert
                source_html.close() # close template file

                html_to_pdf(content, output)
    
            from_template(TEMPLATE_FILE, OUTPUT_FILENAME)
            
            name=user_hashed
            name=name.replace("/","$$$") 
            name=name.replace(".","$$$")
            
            #INPUT_FILENAME = app.config['UPLOAD_FOLDER'] + "/" + name + ".pdf"
            #OUTPUT_TEMPLATE = '/iolcloud/' + name + ".pdf"
            
            access_token = app.config['DROPBOX_ACCESS_TOKEN']
            
            dbx = dropbox.Dropbox(access_token)
            found_template_data = db.session.query(TemplateData).filter_by(user_id=(user_hashed)).all()
            for row in found_template_data:
                
                TemplateData.query.delete()
                db.session.commit()
            
            
                
                
            transferData = TransferData(access_token)   
            file_from = app.config['UPLOAD_FOLDER'] + "/" + name + ".pdf" # This is name of the file to be uploaded
            file_to = "/iolcloud/" + name + ".pdf"  # This is the full path to upload the file to, including name that you wish the file to be called once uploaded.
            print(file_from)
            print(file_to)
            
            try:
                dbx.files_delete_v2("/iolcloud/" + name + ".pdf")
                transferData.upload_file(file_from, file_to)
            except:
                transferData.upload_file(file_from, file_to)
                
                    
            
            result = dbx.files_get_temporary_link(file_to)
            print(result.link)
            
            new_template = TemplateData(found_invoice_data.email, user_hashed, result.link)
            db.session.add(new_template)
            db.session.commit()           
            found_template_data = db.session.query(TemplateData).filter_by(user_id=(user_hashed)).first()
            
            return render_template('invoice-html.html', user=current_user, invoice_data=found_invoice_data, items_data=found_invoice_items, invoice_values=found_invoice_values, profile_data=found_profile_data, image_data=found_image_data, template_data=found_template_data, qrcode_data=found_qrcode_data)   
               
        
        else:
            return render_template('invoice-number.html', user=current_user)
    except Exception as e:
        print(str(e))
        
    #return render_template('invoice.html')
    return 'Done'

@app.route('/editinvoice', methods=['GET', 'POST'])
@login_required
def editinvoice():
    
    user_hashed=current_user.user_id_hash
    sum = 0
    list_sum = []
    formated_float = 0.00
    counter = 0
   
    
    
    try:
        if request.method == 'POST':
            invoice_number=request.form['invoice_number']
            
            found_user_data = db.session.query(User).filter_by(user_id_hash=(user_hashed)).all()
            found_invoice_data = db.session.query(InvoiceData).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).first()
            found_invoice_items = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).all()
            found_invoice_values = db.session.query(InvoiceValues).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).first() 
            found_profile_data = db.session.query(ProfileData).filter_by(user_id=(user_hashed)).first() 
            found_image_data = db.session.query(ImageData).filter_by(user_id=(user_hashed)).first() 
            return render_template('edit-invoice.html', user=current_user, found_invoice_data=found_invoice_data, found_invoice_items=found_invoice_items, found_invoice_values=found_invoice_values)
    except Exception as e:
        print(str(e))
    return 'Done'
    
 
         
@app.route('/invoicebyein', methods=['GET', 'POST'])
@login_required
def invoicebyein():
    user_hashed=current_user.user_id_hash
    
    POST_PER_PAGE = 2

    page = request.args.get('page', 1, type=int)
    if request.method == 'POST':
        session['invoice_ein'] = request.form['invoice_ein']  
    if 'invoice_ein' in session:
        invoice_ein = session['invoice_ein']
        #print(invoice_ein)
    
    found_ein = db.session.query(InvoiceData).filter_by(user_id=(user_hashed), ein=(invoice_ein)).paginate(page=page, per_page=POST_PER_PAGE)
    rows = db.session.query(InvoiceData).filter_by(user_id=(user_hashed), ein=(invoice_ein)).count();
    if rows > 0:
        next_url = url_for('invoicebyein', page=found_ein.next_num) \
            if found_ein.has_next else None
        prev_url = url_for('invoicebyein', page=found_ein.prev_num) \
            if found_ein.has_prev else None
        return render_template('invoice-by-ein.html', found_ein=found_ein, next_url=next_url, prev_url=prev_url, user=current_user)
    else:
        return render_template('no_found_records.html', user=current_user)
            
        
    
        
        
    
        
    #return render_template('invoice.html')
    return 'Done'
    
@app.route('/invoicebynumber', methods=['GET', 'POST'])
@login_required
def invoicebynumber():
    user_hashed=current_user.user_id_hash
    
    #POST_PER_PAGE = 2

    #page = request.args.get('page', 1, type=int)
    if request.method == 'POST':
        
        
    
        found_invoice = db.session.query(InvoiceData).filter_by(user_id=(user_hashed), invoice_number=request.form['invoice_number']).first()
        rows = db.session.query(InvoiceData).filter_by(user_id=(user_hashed), invoice_number=request.form['invoice_number']).count();
        if rows > 0:
            return render_template('invoice-by-number.html', found_invoice=found_invoice, user=current_user)
        else:
            return render_template('no_found_records.html', user=current_user)
            
        
    
        
        
    
        
    #return render_template('invoice.html')
    return 'Done'
    
@app.route('/searchinvoicebyein', methods=['GET', 'POST'])
@login_required
def searchinvoicebyein():
    user_hashed=current_user.user_id_hash
    
    
    return render_template('invoice-ein.html', user=current_user)
    
@app.route('/invoicebydates', methods=['GET', 'POST'])
@login_required
def invoicebydates():
    user_hashed=current_user.user_id_hash
    
    POST_PER_PAGE = 2

    page = request.args.get('page', 1, type=int)
    if request.method == 'POST':
        session['date_start'] = request.form['date_start']
        session['date_end'] = request.form['date_end']
    if 'date_start' in session:
        date_start = session['date_start']
    if 'date_end' in session:
        date_end = session['date_end']
        #print(invoice_ein)
    
    found_date = db.session.query(InvoiceData).filter_by(user_id=(user_hashed)).filter(InvoiceData.invoice_date.between(date_start, date_end)).paginate(page=page, per_page=POST_PER_PAGE)
    rows = db.session.query(InvoiceData).filter_by(user_id=(user_hashed)).filter(InvoiceData.invoice_date.between(date_start, date_end)).count()
    if rows > 0:
        next_url = url_for('invoicebydates', page=found_date.next_num) \
            if found_date.has_next else None
        prev_url = url_for('invoicebydates', page=found_date.prev_num) \
            if found_date.has_prev else None
        return render_template('invoice-by-dates.html', found_date=found_date, next_url=next_url, prev_url=prev_url, user=current_user)
    else:
        return render_template('no_found_records.html', user=current_user)
            
        
    
        
        
    
        
    #return render_template('invoice.html')
    return 'Done'    
    
@app.route('/searchinvoicebydates', methods=['GET', 'POST'])
@login_required
def searchinvoicebydates():
    user_hashed=current_user.user_id_hash
    
    
    return render_template('invoice-dates.html', user=current_user)   
    
@app.route('/searchinvoicebynumber', methods=['GET', 'POST'])
@login_required
def searchinvoicebynumber():
    user_hashed=current_user.user_id_hash
    
    
    return render_template('invoice-number.html', user=current_user)
    
@app.route('/invoicenumberbyein', methods=['GET', 'POST'])
@login_required
def invoicenumberbyein():
    
    user_hashed=current_user.user_id_hash
    sum = 0
    list_sum = []
    formated_float = 0.00
    counter = 0
   
    
    
    try:
        if request.method == 'POST':
            invoice_number=request.form['invoice_number']
            
            found_user_data = db.session.query(User).filter_by(user_id_hash=(user_hashed)).all()
            found_invoice_data = db.session.query(InvoiceData).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).first()
            found_invoice_items = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).all()
            found_invoice_values = db.session.query(InvoiceValues).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).first() 
            found_profile_data = db.session.query(ProfileData).filter_by(user_id=(user_hashed)).first() 
            found_image_data = db.session.query(ImageData).filter_by(user_id=(user_hashed)).first() 
            found_invoice_items_rows = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).count()
            
            name=current_user.user_id_hash
            name=name.replace("/","$$$")
            name=name.replace(".","$$$")
            destination=name+"orig"+".png"
            qrcodepath = os.path.join(app.config['UPLOAD_FOLDER'], destination)
            print('qrcodepath: ', qrcodepath)
            qrcode_string = found_profile_data.businessname + '\n' + 'EIN: ' + found_profile_data.ein
            chars = QRCode(qrcode_string)
            chars.png(qrcodepath, scale=8)
            
            image = PIL.Image.open(os.path.join(app.config['UPLOAD_FOLDER'], destination))
            
            width, height = image.size
            
            #print(width, height)
            finalimagename=name+"qrcode.png" 
            basewidth = 150
            if width > 150:
                img = Image.open(os.path.join(app.config['UPLOAD_FOLDER'], destination))
                wpercent = (basewidth / float(img.size[0]))
                hsize = int((float(img.size[1]) * float(wpercent)))
                img = img.resize((basewidth, hsize), Image.ANTIALIAS)
                img.save(os.path.join(app.config['UPLOAD_FOLDER'], finalimagename))
                new__image = PIL.Image.open(os.path.join(app.config['UPLOAD_FOLDER'], finalimagename))
                width, height = new__image.size
                
            upload_path = "static/uploads"
            os.chdir(upload_path)
            os.remove(destination)
            
            access_token = app.config['DROPBOX_ACCESS_TOKEN']
            transferData = TransferData(access_token)
            
            file_from = finalimagename
            file_to = '/iolcloud/' + finalimagename # The full path to upload the file to, including the file name
            dbx = dropbox.Dropbox(access_token)
            
              # API v2
            #transferData.upload_file(file_from, file_to)
            
            try:
                dbx.files_delete_v2("/iolcloud/" + finalimagename)
                transferData.upload_file(file_from, file_to)
            except:
                transferData.upload_file(file_from, file_to)
    
            #result = dbx.files_get_temporary_link(file_to)
            #dbx.sharing_create_shared_link(path = file_to, short_url=False, pending_upload=None)
            result = dbx.sharing_create_shared_link(path = file_to, short_url=False, pending_upload=None).url
           
            name_url=result.replace("https:","")
            name_url_final=name_url.replace("?dl=0","?raw=1")
            print(result)
            print(name_url)  


        

            #print(url_link)
            os.chdir(r"..")
            
            
            user_hashed=current_user.user_id_hash
            
            found_qrcode_data = db.session.query(QRcodeData).filter_by(user_id=(user_hashed)).all()
            for row in found_qrcode_data:
                QRcodeData.query.delete()
                db.session.commit()
            
            new_image = QRcodeData(user_hashed, finalimagename, name_url_final, width, height)
            db.session.add(new_image)
            db.session.commit()
            
            found_qrcode_data = db.session.query(QRcodeData).filter_by(user_id=(user_hashed)).first()
            
            
               
            POST_PER_PAGE = 7
            page = 1
            query = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).paginate(page=page, per_page=POST_PER_PAGE)
            
            name=user_hashed
            name=name.replace("/","$$$") 
            name=name.replace(".","$$$")
            #write html and pdf code
            print(app.config['UPLOAD_FOLDER'])
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","w")
            f.write("<html><head> \
            </head> \
            <body style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <tr> \
            <td style='vertical-align: top;' width='50%'> \
            <img src='https:" + found_image_data.image_url + "' alt='Logo'> \
            </td> \
            <td style='vertical-align: top; text-align:right;' width='50%'> \
            <span style='text-align:right;'>" + found_profile_data.businessname + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.email + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.ein + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.address1 + "</span><br />")
            f.close()
            if found_profile_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
                f.write("<span>" + found_profile_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html", "a")
            f.write("<span style='text-align:right;'>" + found_profile_data.city + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.state + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.zip + "</span> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
            <tr> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Billing Address</strong></td></tr></table> \
            </td> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Shipping Address</strong></td></tr></table> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <tr> \
            <td style='vertical-align: top;' width='50%' style='text-align:left;'> \
            <span style='text-align:left;'>" + found_invoice_data.businessname + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.email + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.ein + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.address + "</span><br />")
            f.close()
            if found_invoice_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
                f.write("<span style='text-align:left;'>" + found_invoice_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html", "a")
            f.write("<span style='text-align:left;'>" + found_invoice_data.city + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.state + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.zip + "</span> \
            </td> \
            <td style='vertical-align: top; text-align:left;' width='50%'> \
            <span style='text-align:left;'>" + found_invoice_data.businessname_shipping + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.email_shipping + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.ein_shipping + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.address_shipping + "</span><br />")
            f.close()
            if found_invoice_data.address2_shipping != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
                f.write("<span style='text-align:left;'>" + found_invoice_data.address2_shipping + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html", "a")
            f.write("<span style='text-align:left;'>" + found_invoice_data.city_shipping + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.state_shipping + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.zip_shipping + "</span> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 33%'><strong>Invoice Date:</strong>&nbsp;" + str(found_invoice_data.invoice_date) +"</td><td style='width: 33%'><strong>Invoice Number</strong>&nbsp;" + found_invoice_data.invoice_number + "</td><td style='width: 33%'><strong>Taxes</strong>&nbsp;" + found_invoice_data.taxes + "</td></tr>\
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
            f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            for item in found_invoice_items:
                f.write("<tr><td style='width: 25%;'><p><strong>Description</strong></p><p>" + item.item_desc +"</p></td><td style='width: 25%;'><p><strong>Price</strong></p><p>" + format_currency(str(item.item_price), 'USD', locale='en_US') + "</p></td><td style='width: 25%;'><p><strong>Quantity</strong></p><p>" + str(item.item_quant) + "</p></td><td style='width: 25%;'><p><strong>Total</strong></p><p>" + format_currency(str(item.amount), 'USD', locale='en_US') + "</p></td></tr>")
            f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("</table>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width:[] 50%'>" + format_currency(str(found_invoice_values.subtotal), 'USD', locale='en_US') + "</td></tr>")
            f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.taxes), 'USD', locale='en_US') + "</td></tr>")
            f.write("<tr><td style='width: 50%'><strong>Total</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.total), 'USD', locale='en_US') + "</td></tr>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("</table></td></tr></table>")
            f.close()            
            
            access_token = app.config['DROPBOX_ACCESS_TOKEN']
            
            dbx = dropbox.Dropbox(access_token)
            found_html_template_data = db.session.query(TemplateHTMLData).filter_by(user_id=(user_hashed)).all()
            for row in found_html_template_data:
                
                TemplateHTMLData.query.delete()
                db.session.commit()
            
            
                
                
            transferData = TransferData(access_token)   
            file_from = app.config['UPLOAD_FOLDER'] + "/email" + name + ".html" # This is name of the file to be uploaded
            file_to = "/iolcloud/email" + name + ".html"  # This is the full path to upload the file to, including name that you wish the file to be called once uploaded.
            print(file_from)
            print(file_to)
            
            try:
                dbx.files_delete_v2("/iolcloud/email" + name + ".html")
                transferData.upload_file(file_from, file_to)
            except:
                transferData.upload_file(file_from, file_to)
                
                    
            
            result = dbx.files_get_temporary_link(file_to)
            print(result.link)
            
            new_template = TemplateHTMLData(found_invoice_data.email, user_hashed, result.link)
            db.session.add(new_template)
            db.session.commit()           
            found_html_template_data = db.session.query(TemplateHTMLData).filter_by(user_id=(user_hashed)).first()
                        
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","w")
            f.write("<html><head> \
            <style> \
            @page { \
            size: a4 portrait; \
            @frame header_frame {           /* Static frame */ \
            -pdf-frame-content: header_content; \
            left: 50pt; width: 512pt; top: 20pt; height: 170pt; \
            } \
            @frame content_frame {          /* Content Frame */ \
            left: 50pt; width: 512pt; top: 150pt; height: 632pt; \
            } \
           @frame footer_frame {           /* Another static Frame */ \
            -pdf-frame-content: footer_content; \
            left: 50pt; width: 512pt; top: 780pt; height: 20pt; \
            } \
            } \
            </style> \
            </head> \
            <body style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;' id='header_content'> \
            <tr> \
            <td style='vertical-align: top;' width='50%'> \
            <img src='https:" + found_image_data.image_url + "' alt='Logo'> \
            </td> \
            <td style='vertical-align: top; text-align:right;' width='50%'> \
            <span style='text-align:right;'>" + found_profile_data.businessname + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.email + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.ein + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.address1 + "</span><br />")
            f.close()
            if found_profile_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<span>" + found_profile_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html", "a")
            f.write("<span style='text-align:right;'>" + found_profile_data.city + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.state + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.zip + "</span> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
            <tr> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Billing Address</strong></td></tr></table> \
            </td> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Shipping Address</strong></td></tr></table> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
            <tr> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname + "</span><br /> \
            <span>" + found_invoice_data.email + "</span><br /> \
            <span>" + found_invoice_data.ein + "</span><br /> \
            <span>" + found_invoice_data.address + "</span><br />")
            f.close()
            if found_invoice_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<span>" + found_invoice_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html", "a")
            f.write("<span>" + found_invoice_data.city + "</span>&nbsp;<span>" + found_invoice_data.state + "&nbsp;</span>&nbsp;<span>" + found_invoice_data.zip +"</span> \
            </td></tr></table> \
            </td> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname_shipping + "</span><br /> \
            <span>" + found_invoice_data.email_shipping + "</span><br /> \
            <span>" + found_invoice_data.ein_shipping + "</span><br /> \
            <span>" + found_invoice_data.address_shipping + "</span><br />")
            f.close()
            if found_invoice_data.address2_shipping != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<span>" + found_invoice_data.address2_shipping + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
            f.write("<span>" + found_invoice_data.city_shipping + "</span>&nbsp;<span>" + found_invoice_data.state_shipping + "</span>&nbsp;<span>" + found_invoice_data.zip_shipping + "</span> \
            </td></tr></table> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 33%'><strong>Invoice Date:</strong>&nbsp;" + str(found_invoice_data.invoice_date) +"</td><td style='width: 33%'><strong>Invoice Number</strong>&nbsp;" + found_invoice_data.invoice_number + "</td><td style='width: 33%'><strong>Taxes</strong>&nbsp;" + found_invoice_data.taxes + "</td></tr>\
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
            
            for item in query.items:
                f.write("<tr><td style='width: 25%'><span><strong>Description</strong><br />" + item.item_desc +"</span></td><td style='width: 25%'><span><strong>Price</strong><br />" + format_currency(str(item.item_price), 'USD', locale='en_US') + "</span></td><td style='width: 25%'><span><strong>Quantity</strong><br />" + str(item.item_quant) + "</span></td><td style='width: 25%'><span><strong>Total</strong><br />" + format_currency(str(item.amount), 'USD', locale='en_US') + "</span></td></tr>")
                sum += item.amount
                
                list_sum.append(sum)
                counter += 1
            f.write("</table>")                
            res_max = max(list_sum)
            print(res_max)
            print(len(list_sum))
            print(counter)
            print(found_invoice_items_rows)
            print(type(found_invoice_items_rows))
            f.close()
            
            if found_invoice_items_rows > POST_PER_PAGE:
                
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                
                f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
                 <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> ")
                f.close()
                list_number = len(list_sum) - 1
                taxes = float(found_invoice_data.taxes)
                subtotal = round(float(list_sum[list_number]), 2)
                taxes = round(float(list_sum[list_number] * float(taxes/100)), 2)
                amount = round(float(subtotal + taxes), 2)
                print(subtotal)
                
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width: 50%'>" + format_currency(str(subtotal), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(taxes), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Total</strong></td>")
                f.write("<td style='width: 50%'>" + format_currency(str(amount), 'USD', locale='en_US') + "</td></tr>")
                f.write("</table></table>")
                f.close()
                
                while(counter <= found_invoice_items_rows):
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<div><pdf:nextpage></div>")
                    f.close()        
                    page = query.next_num
                    query = query.next(error_out=False)
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%'> \
                <tr> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Billing Address</strong></td></tr></table> \
                </td> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Shipping Address</strong></td></tr></table> \
                </td> \
                </tr> \
                </table> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
                <tr> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname + "</span><br /> \
                <span>" + found_invoice_data.email + "</span><br /> \
                <span>" + found_invoice_data.ein + "</span><br /> \
                <span>" + found_invoice_data.address + "</span><br />")
                    f.close()
                    if found_invoice_data.address2 != '':
                        f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                        f.write("<span>" + found_invoice_data.address2 + "</span><br />")
                        f.close()
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html", "a")
                    f.write("<span>" + found_invoice_data.city + "</span>&nbsp;<span>" + found_invoice_data.state + "&nbsp;</span>&nbsp;<span>" + found_invoice_data.zip +"</span> \
                </td></tr></table> \
                </td> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname_shipping + "</span><br /> \
                <span>" + found_invoice_data.email_shipping + "</span><br /> \
                <span>" + found_invoice_data.ein_shipping + "</span><br /> \
                <span>" + found_invoice_data.address_shipping + "</span><br />")
                    f.close()
                    if found_invoice_data.address2_shipping != '':
                        f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                        f.write("<span>" + found_invoice_data.address2_shipping + "</span><br />")
                        f.close()
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<span>" + found_invoice_data.city_shipping + "</span>&nbsp;<span>" + found_invoice_data.state_shipping + "</span>&nbsp;<span>" + found_invoice_data.zip_shipping + "</span> \
                </td></tr></table> \
                </td> \
                </tr> \
                </table> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
                <tr><td style='width: 33%'><strong>Invoice Date:</strong>&nbsp;" + str(found_invoice_data.invoice_date) +"</td><td style='width: 33%'><strong>Invoice Number</strong>&nbsp;" + found_invoice_data.invoice_number + "</td><td style='width: 33%'><strong>Taxes</strong>&nbsp;" + found_invoice_data.taxes + "</td></tr>\
                </table>")
                    f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
                    f.close()
                
               
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    for item in query.items:
                    
                        f.write("<tr><td style='width: 25%'><span><strong>Description</strong><br />" + item.item_desc +"</span></td><td style='width: 25%'><span><strong>Price</strong><br />" + format_currency(str(item.item_price), 'USD', locale='en_US') + "</span></td><td style='width: 25%'><span><strong>Quantity</strong><br />" + str(item.item_quant) + "</span></td><td style='width: 25%'><span><strong>Total</strong><br />" + format_currency(str(item.amount), 'USD', locale='en_US') + "</span></td></tr>")
                        sum += item.amount
                        list_sum.append(sum)
                        counter += 1
                    f.write("</table>")
                    f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
                    f.close()
                    list_number = len(list_sum) - 1
                    taxes = float(found_invoice_data.taxes)
                    subtotal = round(float(list_sum[list_number]), 2)
                    taxes = round(float(list_sum[list_number] * float(taxes/100)), 2)
                    amount = round(float(subtotal + taxes), 2)
                    print(subtotal)
                
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width: 50%'>" + format_currency(str(subtotal), 'USD', locale='en_US') + "</td></tr>")
                    f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(taxes), 'USD', locale='en_US') + "</td></tr>")
                    f.write("<tr><td style='width: 50%'><strong>Total</strong></td>")
                    f.write("<td style='width: 50%'>" + format_currency(str(amount), 'USD', locale='en_US') + "</td></tr>")
                    f.close()
            
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("</table></table>")
                    f.close()
                    counter += 1
            else:
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("</table>")
                f.close()
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
                f.close()
            
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.subtotal), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.taxes), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Total</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.total), 'USD', locale='en_US') + "</td></tr>")
                f.close()
            
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("</table></table>")
                f.close() 
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
            f.write("<div id='footer_content' style='text-align: center;'>page <pdf:pagenumber> \
            of <pdf:pagecount> \
            </div> \
            </body> \
            </html>")
            
            
            f.close()
            
            OUTPUT_FILENAME = app.config['UPLOAD_FOLDER'] + "/" + name + ".pdf"
            TEMPLATE_FILE = app.config['UPLOAD_FOLDER'] + "/" + name + ".html"
            
            # Methods section ....
            def html_to_pdf(content, output):
            
                # Open file to write
                result_file = open(output, "w+b") # w+b to write in binary mode.

                # convert HTML to PDF
                pisa_status = pisa.CreatePDF(
                content,                   # the HTML to convert
                dest=result_file           # file handle to recieve result
                )           

                # close output file
                result_file.close()

                result = pisa_status.err

                if not result:
                    print("Successfully created PDF")
                else:
                    print("Error: unable to create the PDF")    

                # return False on success and True on errors
                return result



            def from_template(template, output):
   
                # Reading our template
                source_html = open(template, "r")
                content = source_html.read() # the HTML to convert
                source_html.close() # close template file

                html_to_pdf(content, output)
    
            from_template(TEMPLATE_FILE, OUTPUT_FILENAME)
            
            name=user_hashed
            name=name.replace("/","$$$") 
            name=name.replace(".","$$$")
            
            #INPUT_FILENAME = app.config['UPLOAD_FOLDER'] + "/" + name + ".pdf"
            #OUTPUT_TEMPLATE = '/iolcloud/' + name + ".pdf"
            
            access_token = app.config['DROPBOX_ACCESS_TOKEN']
            
            dbx = dropbox.Dropbox(access_token)
            found_template_data = db.session.query(TemplateData).filter_by(user_id=(user_hashed)).all()
            for row in found_template_data:
                
                TemplateData.query.delete()
                db.session.commit()
            
            
                
                
            transferData = TransferData(access_token)   
            file_from = app.config['UPLOAD_FOLDER'] + "/" + name + ".pdf" # This is name of the file to be uploaded
            file_to = "/iolcloud/" + name + ".pdf"  # This is the full path to upload the file to, including name that you wish the file to be called once uploaded.
            print(file_from)
            print(file_to)
            
            try:
                dbx.files_delete_v2("/iolcloud/" + name + ".pdf")
                transferData.upload_file(file_from, file_to)
            except:
                transferData.upload_file(file_from, file_to)
                
                    
            
            result = dbx.files_get_temporary_link(file_to)
            print(result.link)
            
            new_template = TemplateData(found_invoice_data.email, user_hashed, result.link)
            db.session.add(new_template)
            db.session.commit()           
            found_template_data = db.session.query(TemplateData).filter_by(user_id=(user_hashed)).first()
            
            return render_template('invoice-html.html', user=current_user, invoice_data=found_invoice_data, items_data=found_invoice_items, invoice_values=found_invoice_values, profile_data=found_profile_data, image_data=found_image_data, template_data=found_template_data, qrcode_data=found_qrcode_data)   
               
        
        else:
            return render_template('invoice-ein.html', user=current_user)
    except Exception as e:
        print(str(e))
        
    #return render_template('invoice.html')
    return 'Done'
    
@app.route('/invoicenumberresults', methods=['GET', 'POST'])
@login_required
def invoicenumberresults():
    
    user_hashed=current_user.user_id_hash
    sum = 0
    list_sum = []
    formated_float = 0.00
    counter = 0
   
    
    
    try:
        if request.method == 'POST':
            invoice_number=request.form['invoice_number']
            
            found_user_data = db.session.query(User).filter_by(user_id_hash=(user_hashed)).all()
            found_invoice_data = db.session.query(InvoiceData).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).first()
            found_invoice_items = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).all()
            found_invoice_values = db.session.query(InvoiceValues).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).first() 
            found_profile_data = db.session.query(ProfileData).filter_by(user_id=(user_hashed)).first() 
            found_image_data = db.session.query(ImageData).filter_by(user_id=(user_hashed)).first() 
            found_invoice_items_rows = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).count()
            
            name=current_user.user_id_hash
            name=name.replace("/","$$$")
            name=name.replace(".","$$$")
            destination=name+"orig"+".png"
            qrcodepath = os.path.join(app.config['UPLOAD_FOLDER'], destination)
            print('qrcodepath: ', qrcodepath)
            qrcode_string = found_profile_data.businessname + '\n' + 'EIN: ' + found_profile_data.ein
            chars = QRCode(qrcode_string)
            chars.png(qrcodepath, scale=8)
            
            image = PIL.Image.open(os.path.join(app.config['UPLOAD_FOLDER'], destination))
            
            width, height = image.size
            
            #print(width, height)
            finalimagename=name+"qrcode.png" 
            basewidth = 150
            if width > 150:
                img = Image.open(os.path.join(app.config['UPLOAD_FOLDER'], destination))
                wpercent = (basewidth / float(img.size[0]))
                hsize = int((float(img.size[1]) * float(wpercent)))
                img = img.resize((basewidth, hsize), Image.ANTIALIAS)
                img.save(os.path.join(app.config['UPLOAD_FOLDER'], finalimagename))
                new__image = PIL.Image.open(os.path.join(app.config['UPLOAD_FOLDER'], finalimagename))
                width, height = new__image.size
                
            upload_path = "static/uploads"
            os.chdir(upload_path)
            os.remove(destination)
            
            access_token = app.config['DROPBOX_ACCESS_TOKEN']
            transferData = TransferData(access_token)
            
            file_from = finalimagename
            file_to = '/iolcloud/' + finalimagename # The full path to upload the file to, including the file name
            dbx = dropbox.Dropbox(access_token)
            
              # API v2
            #transferData.upload_file(file_from, file_to)
            
            try:
                dbx.files_delete_v2("/iolcloud/" + finalimagename)
                transferData.upload_file(file_from, file_to)
            except:
                transferData.upload_file(file_from, file_to)
    
            #result = dbx.files_get_temporary_link(file_to)
            #dbx.sharing_create_shared_link(path = file_to, short_url=False, pending_upload=None)
            result = dbx.sharing_create_shared_link(path = file_to, short_url=False, pending_upload=None).url
           
            name_url=result.replace("https:","")
            name_url_final=name_url.replace("?dl=0","?raw=1")
            print(result)
            print(name_url)  


        

            #print(url_link)
            os.chdir(r"..")
            
            
            user_hashed=current_user.user_id_hash
            
            found_qrcode_data = db.session.query(QRcodeData).filter_by(user_id=(user_hashed)).all()
            for row in found_qrcode_data:
                QRcodeData.query.delete()
                db.session.commit()
            
            new_image = QRcodeData(user_hashed, finalimagename, name_url_final, width, height)
            db.session.add(new_image)
            db.session.commit()
            
            found_qrcode_data = db.session.query(QRcodeData).filter_by(user_id=(user_hashed)).first()
            
            
               
            POST_PER_PAGE = 7
            page = 1
            query = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).paginate(page=page, per_page=POST_PER_PAGE)
            
            name=user_hashed
            name=name.replace("/","$$$") 
            name=name.replace(".","$$$")
            #write html and pdf code
            print(app.config['UPLOAD_FOLDER'])
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","w")
            f.write("<html><head> \
            </head> \
            <body style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <tr> \
            <td style='vertical-align: top;' width='50%'> \
            <img src='https:" + found_image_data.image_url + "' alt='Logo'> \
            </td> \
            <td style='vertical-align: top; text-align:right;' width='50%'> \
            <span style='text-align:right;'>" + found_profile_data.businessname + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.email + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.ein + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.address1 + "</span><br />")
            f.close()
            if found_profile_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
                f.write("<span>" + found_profile_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html", "a")
            f.write("<span style='text-align:right;'>" + found_profile_data.city + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.state + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.zip + "</span> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
            <tr> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Billing Address</strong></td></tr></table> \
            </td> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Shipping Address</strong></td></tr></table> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <tr> \
            <td style='vertical-align: top;' width='50%' style='text-align:left;'> \
            <span style='text-align:left;'>" + found_invoice_data.businessname + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.email + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.ein + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.address + "</span><br />")
            f.close()
            if found_invoice_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
                f.write("<span style='text-align:left;'>" + found_invoice_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html", "a")
            f.write("<span style='text-align:left;'>" + found_invoice_data.city + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.state + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.zip + "</span> \
            </td> \
            <td style='vertical-align: top; text-align:left;' width='50%'> \
            <span style='text-align:left;'>" + found_invoice_data.businessname_shipping + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.email_shipping + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.ein_shipping + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.address_shipping + "</span><br />")
            f.close()
            if found_invoice_data.address2_shipping != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
                f.write("<span style='text-align:left;'>" + found_invoice_data.address2_shipping + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html", "a")
            f.write("<span style='text-align:left;'>" + found_invoice_data.city_shipping + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.state_shipping + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.zip_shipping + "</span> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 33%'><strong>Invoice Date:</strong>&nbsp;" + str(found_invoice_data.invoice_date) +"</td><td style='width: 33%'><strong>Invoice Number</strong>&nbsp;" + found_invoice_data.invoice_number + "</td><td style='width: 33%'><strong>Taxes</strong>&nbsp;" + found_invoice_data.taxes + "</td></tr>\
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
            f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            for item in found_invoice_items:
                f.write("<tr><td style='width: 25%;'><p><strong>Description</strong></p><p>" + item.item_desc +"</p></td><td style='width: 25%;'><p><strong>Price</strong></p><p>" + format_currency(str(item.item_price), 'USD', locale='en_US') + "</p></td><td style='width: 25%;'><p><strong>Quantity</strong></p><p>" + str(item.item_quant) + "</p></td><td style='width: 25%;'><p><strong>Total</strong></p><p>" + format_currency(str(item.amount), 'USD', locale='en_US') + "</p></td></tr>")
            f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("</table>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width:[] 50%'>" + format_currency(str(found_invoice_values.subtotal), 'USD', locale='en_US') + "</td></tr>")
            f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.taxes), 'USD', locale='en_US') + "</td></tr>")
            f.write("<tr><td style='width: 50%'><strong>Total</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.total), 'USD', locale='en_US') + "</td></tr>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("</table></td></tr></table>")
            f.close()            
            
            access_token = app.config['DROPBOX_ACCESS_TOKEN']
            
            dbx = dropbox.Dropbox(access_token)
            found_html_template_data = db.session.query(TemplateHTMLData).filter_by(user_id=(user_hashed)).all()
            for row in found_html_template_data:
                
                TemplateHTMLData.query.delete()
                db.session.commit()
            
            
                
                
            transferData = TransferData(access_token)   
            file_from = app.config['UPLOAD_FOLDER'] + "/email" + name + ".html" # This is name of the file to be uploaded
            file_to = "/iolcloud/email" + name + ".html"  # This is the full path to upload the file to, including name that you wish the file to be called once uploaded.
            print(file_from)
            print(file_to)
            
            try:
                dbx.files_delete_v2("/iolcloud/email" + name + ".html")
                transferData.upload_file(file_from, file_to)
            except:
                transferData.upload_file(file_from, file_to)
                
                    
            
            result = dbx.files_get_temporary_link(file_to)
            print(result.link)
            
            new_template = TemplateHTMLData(found_invoice_data.email, user_hashed, result.link)
            db.session.add(new_template)
            db.session.commit()           
            found_html_template_data = db.session.query(TemplateHTMLData).filter_by(user_id=(user_hashed)).first()
                        
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","w")
            f.write("<html><head> \
            <style> \
            @page { \
            size: a4 portrait; \
            @frame header_frame {           /* Static frame */ \
            -pdf-frame-content: header_content; \
            left: 50pt; width: 512pt; top: 20pt; height: 170pt; \
            } \
            @frame content_frame {          /* Content Frame */ \
            left: 50pt; width: 512pt; top: 150pt; height: 632pt; \
            } \
           @frame footer_frame {           /* Another static Frame */ \
            -pdf-frame-content: footer_content; \
            left: 50pt; width: 512pt; top: 780pt; height: 20pt; \
            } \
            } \
            </style> \
            </head> \
            <body style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;' id='header_content'> \
            <tr> \
            <td style='vertical-align: top;' width='50%'> \
            <img src='https:" + found_image_data.image_url + "' alt='Logo'> \
            </td> \
            <td style='vertical-align: top; text-align:right;' width='50%'> \
            <span style='text-align:right;'>" + found_profile_data.businessname + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.email + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.ein + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.address1 + "</span><br />")
            f.close()
            if found_profile_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<span>" + found_profile_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html", "a")
            f.write("<span style='text-align:right;'>" + found_profile_data.city + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.state + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.zip + "</span> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
            <tr> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Billing Address</strong></td></tr></table> \
            </td> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Shipping Address</strong></td></tr></table> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
            <tr> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname + "</span><br /> \
            <span>" + found_invoice_data.email + "</span><br /> \
            <span>" + found_invoice_data.ein + "</span><br /> \
            <span>" + found_invoice_data.address + "</span><br />")
            f.close()
            if found_invoice_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<span>" + found_invoice_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html", "a")
            f.write("<span>" + found_invoice_data.city + "</span>&nbsp;<span>" + found_invoice_data.state + "&nbsp;</span>&nbsp;<span>" + found_invoice_data.zip +"</span> \
            </td></tr></table> \
            </td> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname_shipping + "</span><br /> \
            <span>" + found_invoice_data.email_shipping + "</span><br /> \
            <span>" + found_invoice_data.ein_shipping + "</span><br /> \
            <span>" + found_invoice_data.address_shipping + "</span><br />")
            f.close()
            if found_invoice_data.address2_shipping != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<span>" + found_invoice_data.address2_shipping + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
            f.write("<span>" + found_invoice_data.city_shipping + "</span>&nbsp;<span>" + found_invoice_data.state_shipping + "</span>&nbsp;<span>" + found_invoice_data.zip_shipping + "</span> \
            </td></tr></table> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 33%'><strong>Invoice Date:</strong>&nbsp;" + str(found_invoice_data.invoice_date) +"</td><td style='width: 33%'><strong>Invoice Number</strong>&nbsp;" + found_invoice_data.invoice_number + "</td><td style='width: 33%'><strong>Taxes</strong>&nbsp;" + found_invoice_data.taxes + "</td></tr>\
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
            
            for item in query.items:
                f.write("<tr><td style='width: 25%'><span><strong>Description</strong><br />" + item.item_desc +"</span></td><td style='width: 25%'><span><strong>Price</strong><br />" + format_currency(str(item.item_price), 'USD', locale='en_US') + "</span></td><td style='width: 25%'><span><strong>Quantity</strong><br />" + str(item.item_quant) + "</span></td><td style='width: 25%'><span><strong>Total</strong><br />" + format_currency(str(item.amount), 'USD', locale='en_US') + "</span></td></tr>")
                sum += item.amount
                
                list_sum.append(sum)
                counter += 1
            f.write("</table>")                
            res_max = max(list_sum)
            print(res_max)
            print(len(list_sum))
            print(counter)
            print(found_invoice_items_rows)
            print(type(found_invoice_items_rows))
            f.close()
            
            if found_invoice_items_rows > POST_PER_PAGE:
                
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                
                f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
                 <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> ")
                f.close()
                list_number = len(list_sum) - 1
                taxes = float(found_invoice_data.taxes)
                subtotal = round(float(list_sum[list_number]), 2)
                taxes = round(float(list_sum[list_number] * float(taxes/100)), 2)
                amount = round(float(subtotal + taxes), 2)
                print(subtotal)
                
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width: 50%'>" + format_currency(str(subtotal), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(taxes), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Total</strong></td>")
                f.write("<td style='width: 50%'>" + format_currency(str(amount), 'USD', locale='en_US') + "</td></tr>")
                f.write("</table></table>")
                f.close()
                
                while(counter <= found_invoice_items_rows):
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<div><pdf:nextpage></div>")
                    f.close()        
                    page = query.next_num
                    query = query.next(error_out=False)
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%'> \
                <tr> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Billing Address</strong></td></tr></table> \
                </td> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Shipping Address</strong></td></tr></table> \
                </td> \
                </tr> \
                </table> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
                <tr> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname + "</span><br /> \
                <span>" + found_invoice_data.email + "</span><br /> \
                <span>" + found_invoice_data.ein + "</span><br /> \
                <span>" + found_invoice_data.address + "</span><br />")
                    f.close()
                    if found_invoice_data.address2 != '':
                        f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                        f.write("<span>" + found_invoice_data.address2 + "</span><br />")
                        f.close()
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html", "a")
                    f.write("<span>" + found_invoice_data.city + "</span>&nbsp;<span>" + found_invoice_data.state + "&nbsp;</span>&nbsp;<span>" + found_invoice_data.zip +"</span> \
                </td></tr></table> \
                </td> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname_shipping + "</span><br /> \
                <span>" + found_invoice_data.email_shipping + "</span><br /> \
                <span>" + found_invoice_data.ein_shipping + "</span><br /> \
                <span>" + found_invoice_data.address_shipping + "</span><br />")
                    f.close()
                    if found_invoice_data.address2_shipping != '':
                        f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                        f.write("<span>" + found_invoice_data.address2_shipping + "</span><br />")
                        f.close()
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<span>" + found_invoice_data.city_shipping + "</span>&nbsp;<span>" + found_invoice_data.state_shipping + "</span>&nbsp;<span>" + found_invoice_data.zip_shipping + "</span> \
                </td></tr></table> \
                </td> \
                </tr> \
                </table> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
                <tr><td style='width: 33%'><strong>Invoice Date:</strong>&nbsp;" + str(found_invoice_data.invoice_date) +"</td><td style='width: 33%'><strong>Invoice Number</strong>&nbsp;" + found_invoice_data.invoice_number + "</td><td style='width: 33%'><strong>Taxes</strong>&nbsp;" + found_invoice_data.taxes + "</td></tr>\
                </table>")
                    f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
                    f.close()
                
               
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    for item in query.items:
                    
                        f.write("<tr><td style='width: 25%'><span><strong>Description</strong><br />" + item.item_desc +"</span></td><td style='width: 25%'><span><strong>Price</strong><br />" + format_currency(str(item.item_price), 'USD', locale='en_US') + "</span></td><td style='width: 25%'><span><strong>Quantity</strong><br />" + str(item.item_quant) + "</span></td><td style='width: 25%'><span><strong>Total</strong><br />" + format_currency(str(item.amount), 'USD', locale='en_US') + "</span></td></tr>")
                        sum += item.amount
                        list_sum.append(sum)
                        counter += 1
                    f.write("</table>")
                    f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
                    f.close()
                    list_number = len(list_sum) - 1
                    taxes = float(found_invoice_data.taxes)
                    subtotal = round(float(list_sum[list_number]), 2)
                    taxes = round(float(list_sum[list_number] * float(taxes/100)), 2)
                    amount = round(float(subtotal + taxes), 2)
                    print(subtotal)
                
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width: 50%'>" + format_currency(str(subtotal), 'USD', locale='en_US') + "</td></tr>")
                    f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(taxes), 'USD', locale='en_US') + "</td></tr>")
                    f.write("<tr><td style='width: 50%'><strong>Total</strong></td>")
                    f.write("<td style='width: 50%'>" + format_currency(str(amount), 'USD', locale='en_US') + "</td></tr>")
                    f.close()
            
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("</table></table>")
                    f.close()
                    counter += 1
            else:
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("</table>")
                f.close()
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
                f.close()
            
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.subtotal), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.taxes), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Total</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.total), 'USD', locale='en_US') + "</td></tr>")
                f.close()
            
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("</table></table>")
                f.close() 
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
            f.write("<div id='footer_content' style='text-align: center;'>page <pdf:pagenumber> \
            of <pdf:pagecount> \
            </div> \
            </body> \
            </html>")
            
            
            f.close()
            
            OUTPUT_FILENAME = app.config['UPLOAD_FOLDER'] + "/" + name + ".pdf"
            TEMPLATE_FILE = app.config['UPLOAD_FOLDER'] + "/" + name + ".html"
            
            # Methods section ....
            def html_to_pdf(content, output):
            
                # Open file to write
                result_file = open(output, "w+b") # w+b to write in binary mode.

                # convert HTML to PDF
                pisa_status = pisa.CreatePDF(
                content,                   # the HTML to convert
                dest=result_file           # file handle to recieve result
                )           

                # close output file
                result_file.close()

                result = pisa_status.err

                if not result:
                    print("Successfully created PDF")
                else:
                    print("Error: unable to create the PDF")    

                # return False on success and True on errors
                return result



            def from_template(template, output):
   
                # Reading our template
                source_html = open(template, "r")
                content = source_html.read() # the HTML to convert
                source_html.close() # close template file

                html_to_pdf(content, output)
    
            from_template(TEMPLATE_FILE, OUTPUT_FILENAME)
            
            name=user_hashed
            name=name.replace("/","$$$") 
            name=name.replace(".","$$$")
            
            #INPUT_FILENAME = app.config['UPLOAD_FOLDER'] + "/" + name + ".pdf"
            #OUTPUT_TEMPLATE = '/iolcloud/' + name + ".pdf"
            
            access_token = app.config['DROPBOX_ACCESS_TOKEN']
            
            dbx = dropbox.Dropbox(access_token)
            found_template_data = db.session.query(TemplateData).filter_by(user_id=(user_hashed)).all()
            for row in found_template_data:
                
                TemplateData.query.delete()
                db.session.commit()
            
            
                
                
            transferData = TransferData(access_token)   
            file_from = app.config['UPLOAD_FOLDER'] + "/" + name + ".pdf" # This is name of the file to be uploaded
            file_to = "/iolcloud/" + name + ".pdf"  # This is the full path to upload the file to, including name that you wish the file to be called once uploaded.
            print(file_from)
            print(file_to)
            
            try:
                dbx.files_delete_v2("/iolcloud/" + name + ".pdf")
                transferData.upload_file(file_from, file_to)
            except:
                transferData.upload_file(file_from, file_to)
                
                    
            
            result = dbx.files_get_temporary_link(file_to)
            print(result.link)
            
            new_template = TemplateData(found_invoice_data.email, user_hashed, result.link)
            db.session.add(new_template)
            db.session.commit()           
            found_template_data = db.session.query(TemplateData).filter_by(user_id=(user_hashed)).first()
            
            return render_template('invoice-html.html', user=current_user, invoice_data=found_invoice_data, items_data=found_invoice_items, invoice_values=found_invoice_values, profile_data=found_profile_data, image_data=found_image_data, template_data=found_template_data, qrcode_data=found_qrcode_data)   
               
        
        else:
            return render_template('invoice-number.html', user=current_user)
    except Exception as e:
        print(str(e))
        
    #return render_template('invoice.html')
    return 'Done'

@app.route('/invoicenumberbydate', methods=['GET', 'POST'])
@login_required
def invoicenumberbydate():
    
    user_hashed=current_user.user_id_hash
    sum = 0
    list_sum = []
    formated_float = 0.00
    counter = 0
   
    
    
    try:
        if request.method == 'POST':
            invoice_number=request.form['invoice_number']
            
            found_user_data = db.session.query(User).filter_by(user_id_hash=(user_hashed)).all()
            found_invoice_data = db.session.query(InvoiceData).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).first()
            found_invoice_items = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).all()
            found_invoice_values = db.session.query(InvoiceValues).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).first() 
            found_profile_data = db.session.query(ProfileData).filter_by(user_id=(user_hashed)).first() 
            found_image_data = db.session.query(ImageData).filter_by(user_id=(user_hashed)).first() 
            found_invoice_items_rows = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).count()
            
            name=current_user.user_id_hash
            name=name.replace("/","$$$")
            name=name.replace(".","$$$")
            destination=name+"orig"+".png"
            qrcodepath = os.path.join(app.config['UPLOAD_FOLDER'], destination)
            print('qrcodepath: ', qrcodepath)
            qrcode_string = found_profile_data.businessname + '\n' + 'EIN: ' + found_profile_data.ein
            chars = QRCode(qrcode_string)
            chars.png(qrcodepath, scale=8)
            
            image = PIL.Image.open(os.path.join(app.config['UPLOAD_FOLDER'], destination))
            
            width, height = image.size
            
            #print(width, height)
            finalimagename=name+"qrcode.png" 
            basewidth = 150
            if width > 150:
                img = Image.open(os.path.join(app.config['UPLOAD_FOLDER'], destination))
                wpercent = (basewidth / float(img.size[0]))
                hsize = int((float(img.size[1]) * float(wpercent)))
                img = img.resize((basewidth, hsize), Image.ANTIALIAS)
                img.save(os.path.join(app.config['UPLOAD_FOLDER'], finalimagename))
                new__image = PIL.Image.open(os.path.join(app.config['UPLOAD_FOLDER'], finalimagename))
                width, height = new__image.size
                
            upload_path = "static/uploads"
            os.chdir(upload_path)
            os.remove(destination)
            
            access_token = app.config['DROPBOX_ACCESS_TOKEN']
            transferData = TransferData(access_token)
            
            file_from = finalimagename
            file_to = '/iolcloud/' + finalimagename # The full path to upload the file to, including the file name
            dbx = dropbox.Dropbox(access_token)
            
              # API v2
            #transferData.upload_file(file_from, file_to)
            
            try:
                dbx.files_delete_v2("/iolcloud/" + finalimagename)
                transferData.upload_file(file_from, file_to)
            except:
                transferData.upload_file(file_from, file_to)
    
            #result = dbx.files_get_temporary_link(file_to)
            #dbx.sharing_create_shared_link(path = file_to, short_url=False, pending_upload=None)
            result = dbx.sharing_create_shared_link(path = file_to, short_url=False, pending_upload=None).url
           
            name_url=result.replace("https:","")
            name_url_final=name_url.replace("?dl=0","?raw=1")
            print(result)
            print(name_url)  


        

            #print(url_link)
            os.chdir(r"..")
            
            
            user_hashed=current_user.user_id_hash
            
            found_qrcode_data = db.session.query(QRcodeData).filter_by(user_id=(user_hashed)).all()
            for row in found_qrcode_data:
                QRcodeData.query.delete()
                db.session.commit()
            
            new_image = QRcodeData(user_hashed, finalimagename, name_url_final, width, height)
            db.session.add(new_image)
            db.session.commit()
            
            found_qrcode_data = db.session.query(QRcodeData).filter_by(user_id=(user_hashed)).first()
            
            
               
            POST_PER_PAGE = 7
            page = 1
            query = db.session.query(InvoiceItems).filter_by(user_id=(user_hashed), invoice_number=(request.form['invoice_number'])).paginate(page=page, per_page=POST_PER_PAGE)
            
            name=user_hashed
            name=name.replace("/","$$$") 
            name=name.replace(".","$$$")
            #write html and pdf code
            print(app.config['UPLOAD_FOLDER'])
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","w")
            f.write("<html><head> \
            </head> \
            <body style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <tr> \
            <td style='vertical-align: top;' width='50%'> \
            <img src='https:" + found_image_data.image_url + "' alt='Logo'> \
            </td> \
            <td style='vertical-align: top; text-align:right;' width='50%'> \
            <span style='text-align:right;'>" + found_profile_data.businessname + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.email + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.ein + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.address1 + "</span><br />")
            f.close()
            if found_profile_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
                f.write("<span>" + found_profile_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html", "a")
            f.write("<span style='text-align:right;'>" + found_profile_data.city + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.state + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.zip + "</span> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
            <tr> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Billing Address</strong></td></tr></table> \
            </td> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Shipping Address</strong></td></tr></table> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <tr> \
            <td style='vertical-align: top;' width='50%' style='text-align:left;'> \
            <span style='text-align:left;'>" + found_invoice_data.businessname + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.email + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.ein + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.address + "</span><br />")
            f.close()
            if found_invoice_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
                f.write("<span style='text-align:left;'>" + found_invoice_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html", "a")
            f.write("<span style='text-align:left;'>" + found_invoice_data.city + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.state + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.zip + "</span> \
            </td> \
            <td style='vertical-align: top; text-align:left;' width='50%'> \
            <span style='text-align:left;'>" + found_invoice_data.businessname_shipping + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.email_shipping + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.ein_shipping + "</span><br /> \
            <span style='text-align:left;'>" + found_invoice_data.address_shipping + "</span><br />")
            f.close()
            if found_invoice_data.address2_shipping != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
                f.write("<span style='text-align:left;'>" + found_invoice_data.address2_shipping + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html", "a")
            f.write("<span style='text-align:left;'>" + found_invoice_data.city_shipping + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.state_shipping + "</span>&nbsp;<span style='text-align:left;'>" + found_invoice_data.zip_shipping + "</span> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 33%'><strong>Invoice Date:</strong>&nbsp;" + str(found_invoice_data.invoice_date) +"</td><td style='width: 33%'><strong>Invoice Number</strong>&nbsp;" + found_invoice_data.invoice_number + "</td><td style='width: 33%'><strong>Taxes</strong>&nbsp;" + found_invoice_data.taxes + "</td></tr>\
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
            f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            for item in found_invoice_items:
                f.write("<tr><td style='width: 25%;'><p><strong>Description</strong></p><p>" + item.item_desc +"</p></td><td style='width: 25%;'><p><strong>Price</strong></p><p>" + format_currency(str(item.item_price), 'USD', locale='en_US') + "</p></td><td style='width: 25%;'><p><strong>Quantity</strong></p><p>" + str(item.item_quant) + "</p></td><td style='width: 25%;'><p><strong>Total</strong></p><p>" + format_currency(str(item.amount), 'USD', locale='en_US') + "</p></td></tr>")
            f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("</table>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width:[] 50%'>" + format_currency(str(found_invoice_values.subtotal), 'USD', locale='en_US') + "</td></tr>")
            f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.taxes), 'USD', locale='en_US') + "</td></tr>")
            f.write("<tr><td style='width: 50%'><strong>Total</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.total), 'USD', locale='en_US') + "</td></tr>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" + "email" + name + ".html","a")
            f.write("</table></td></tr></table>")
            f.close()            
            
            access_token = app.config['DROPBOX_ACCESS_TOKEN']
            
            dbx = dropbox.Dropbox(access_token)
            found_html_template_data = db.session.query(TemplateHTMLData).filter_by(user_id=(user_hashed)).all()
            for row in found_html_template_data:
                
                TemplateHTMLData.query.delete()
                db.session.commit()
            
            
                
                
            transferData = TransferData(access_token)   
            file_from = app.config['UPLOAD_FOLDER'] + "/email" + name + ".html" # This is name of the file to be uploaded
            file_to = "/iolcloud/email" + name + ".html"  # This is the full path to upload the file to, including name that you wish the file to be called once uploaded.
            print(file_from)
            print(file_to)
            
            try:
                dbx.files_delete_v2("/iolcloud/email" + name + ".html")
                transferData.upload_file(file_from, file_to)
            except:
                transferData.upload_file(file_from, file_to)
                
                    
            
            result = dbx.files_get_temporary_link(file_to)
            print(result.link)
            
            new_template = TemplateHTMLData(found_invoice_data.email, user_hashed, result.link)
            db.session.add(new_template)
            db.session.commit()           
            found_html_template_data = db.session.query(TemplateHTMLData).filter_by(user_id=(user_hashed)).first()
                        
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","w")
            f.write("<html><head> \
            <style> \
            @page { \
            size: a4 portrait; \
            @frame header_frame {           /* Static frame */ \
            -pdf-frame-content: header_content; \
            left: 50pt; width: 512pt; top: 20pt; height: 170pt; \
            } \
            @frame content_frame {          /* Content Frame */ \
            left: 50pt; width: 512pt; top: 150pt; height: 632pt; \
            } \
           @frame footer_frame {           /* Another static Frame */ \
            -pdf-frame-content: footer_content; \
            left: 50pt; width: 512pt; top: 780pt; height: 20pt; \
            } \
            } \
            </style> \
            </head> \
            <body style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;' id='header_content'> \
            <tr> \
            <td style='vertical-align: top;' width='50%'> \
            <img src='https:" + found_image_data.image_url + "' alt='Logo'> \
            </td> \
            <td style='vertical-align: top; text-align:right;' width='50%'> \
            <span style='text-align:right;'>" + found_profile_data.businessname + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.email + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.ein + "</span><br /> \
            <span style='text-align:right;'>" + found_profile_data.address1 + "</span><br />")
            f.close()
            if found_profile_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<span>" + found_profile_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html", "a")
            f.write("<span style='text-align:right;'>" + found_profile_data.city + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.state + "</span>&nbsp;<span style='text-align:right;'>" + found_profile_data.zip + "</span> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
            <tr> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Billing Address</strong></td></tr></table> \
            </td> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Shipping Address</strong></td></tr></table> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
            <tr> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname + "</span><br /> \
            <span>" + found_invoice_data.email + "</span><br /> \
            <span>" + found_invoice_data.ein + "</span><br /> \
            <span>" + found_invoice_data.address + "</span><br />")
            f.close()
            if found_invoice_data.address2 != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<span>" + found_invoice_data.address2 + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html", "a")
            f.write("<span>" + found_invoice_data.city + "</span>&nbsp;<span>" + found_invoice_data.state + "&nbsp;</span>&nbsp;<span>" + found_invoice_data.zip +"</span> \
            </td></tr></table> \
            </td> \
            <td style='width=50%'> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname_shipping + "</span><br /> \
            <span>" + found_invoice_data.email_shipping + "</span><br /> \
            <span>" + found_invoice_data.ein_shipping + "</span><br /> \
            <span>" + found_invoice_data.address_shipping + "</span><br />")
            f.close()
            if found_invoice_data.address2_shipping != '':
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<span>" + found_invoice_data.address2_shipping + "</span><br />")
                f.close()
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
            f.write("<span>" + found_invoice_data.city_shipping + "</span>&nbsp;<span>" + found_invoice_data.state_shipping + "</span>&nbsp;<span>" + found_invoice_data.zip_shipping + "</span> \
            </td></tr></table> \
            </td> \
            </tr> \
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 33%'><strong>Invoice Date:</strong>&nbsp;" + str(found_invoice_data.invoice_date) +"</td><td style='width: 33%'><strong>Invoice Number</strong>&nbsp;" + found_invoice_data.invoice_number + "</td><td style='width: 33%'><strong>Taxes</strong>&nbsp;" + found_invoice_data.taxes + "</td></tr>\
            </table> \
            <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
            f.close()
            
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
            
            for item in query.items:
                f.write("<tr><td style='width: 25%'><span><strong>Description</strong><br />" + item.item_desc +"</span></td><td style='width: 25%'><span><strong>Price</strong><br />" + format_currency(str(item.item_price), 'USD', locale='en_US') + "</span></td><td style='width: 25%'><span><strong>Quantity</strong><br />" + str(item.item_quant) + "</span></td><td style='width: 25%'><span><strong>Total</strong><br />" + format_currency(str(item.amount), 'USD', locale='en_US') + "</span></td></tr>")
                sum += item.amount
                
                list_sum.append(sum)
                counter += 1
            f.write("</table>")                
            res_max = max(list_sum)
            print(res_max)
            print(len(list_sum))
            print(counter)
            print(found_invoice_items_rows)
            print(type(found_invoice_items_rows))
            f.close()
            
            if found_invoice_items_rows > POST_PER_PAGE:
                
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                
                f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
                 <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> ")
                f.close()
                list_number = len(list_sum) - 1
                taxes = float(found_invoice_data.taxes)
                subtotal = round(float(list_sum[list_number]), 2)
                taxes = round(float(list_sum[list_number] * float(taxes/100)), 2)
                amount = round(float(subtotal + taxes), 2)
                print(subtotal)
                
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width: 50%'>" + format_currency(str(subtotal), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(taxes), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Total</strong></td>")
                f.write("<td style='width: 50%'>" + format_currency(str(amount), 'USD', locale='en_US') + "</td></tr>")
                f.write("</table></table>")
                f.close()
                
                while(counter <= found_invoice_items_rows):
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<div><pdf:nextpage></div>")
                    f.close()        
                    page = query.next_num
                    query = query.next(error_out=False)
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%'> \
                <tr> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Billing Address</strong></td></tr></table> \
                </td> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 20px;'><tr><td style='width=100%'><strong>Shipping Address</strong></td></tr></table> \
                </td> \
                </tr> \
                </table> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%'> \
                <tr> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname + "</span><br /> \
                <span>" + found_invoice_data.email + "</span><br /> \
                <span>" + found_invoice_data.ein + "</span><br /> \
                <span>" + found_invoice_data.address + "</span><br />")
                    f.close()
                    if found_invoice_data.address2 != '':
                        f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                        f.write("<span>" + found_invoice_data.address2 + "</span><br />")
                        f.close()
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html", "a")
                    f.write("<span>" + found_invoice_data.city + "</span>&nbsp;<span>" + found_invoice_data.state + "&nbsp;</span>&nbsp;<span>" + found_invoice_data.zip +"</span> \
                </td></tr></table> \
                </td> \
                <td style='width=50%'> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px;'><tr><td style='width=100%'><span>" + found_invoice_data.businessname_shipping + "</span><br /> \
                <span>" + found_invoice_data.email_shipping + "</span><br /> \
                <span>" + found_invoice_data.ein_shipping + "</span><br /> \
                <span>" + found_invoice_data.address_shipping + "</span><br />")
                    f.close()
                    if found_invoice_data.address2_shipping != '':
                        f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                        f.write("<span>" + found_invoice_data.address2_shipping + "</span><br />")
                        f.close()
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<span>" + found_invoice_data.city_shipping + "</span>&nbsp;<span>" + found_invoice_data.state_shipping + "</span>&nbsp;<span>" + found_invoice_data.zip_shipping + "</span> \
                </td></tr></table> \
                </td> \
                </tr> \
                </table> \
                <table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
                <tr><td style='width: 33%'><strong>Invoice Date:</strong>&nbsp;" + str(found_invoice_data.invoice_date) +"</td><td style='width: 33%'><strong>Invoice Number</strong>&nbsp;" + found_invoice_data.invoice_number + "</td><td style='width: 33%'><strong>Taxes</strong>&nbsp;" + found_invoice_data.taxes + "</td></tr>\
                </table>")
                    f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
                    f.close()
                
               
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    for item in query.items:
                    
                        f.write("<tr><td style='width: 25%'><span><strong>Description</strong><br />" + item.item_desc +"</span></td><td style='width: 25%'><span><strong>Price</strong><br />" + format_currency(str(item.item_price), 'USD', locale='en_US') + "</span></td><td style='width: 25%'><span><strong>Quantity</strong><br />" + str(item.item_quant) + "</span></td><td style='width: 25%'><span><strong>Total</strong><br />" + format_currency(str(item.amount), 'USD', locale='en_US') + "</span></td></tr>")
                        sum += item.amount
                        list_sum.append(sum)
                        counter += 1
                    f.write("</table>")
                    f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
                    f.close()
                    list_number = len(list_sum) - 1
                    taxes = float(found_invoice_data.taxes)
                    subtotal = round(float(list_sum[list_number]), 2)
                    taxes = round(float(list_sum[list_number] * float(taxes/100)), 2)
                    amount = round(float(subtotal + taxes), 2)
                    print(subtotal)
                
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width: 50%'>" + format_currency(str(subtotal), 'USD', locale='en_US') + "</td></tr>")
                    f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(taxes), 'USD', locale='en_US') + "</td></tr>")
                    f.write("<tr><td style='width: 50%'><strong>Total</strong></td>")
                    f.write("<td style='width: 50%'>" + format_currency(str(amount), 'USD', locale='en_US') + "</td></tr>")
                    f.close()
            
                    f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                    f.write("</table></table>")
                    f.close()
                    counter += 1
            else:
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("</table>")
                f.close()
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'> \
            <tr><td style='width: 50%'>" + "<img src='https:" + found_qrcode_data.image_url + "' alt='QRcode'>" + "</td><td style='width: 50%'><table border='0' cellspacing='5' cellpadding='5' width='100%' style='font-family: Arial, Helvetica, Verdana; font-size: 14px; margin-top:20px;'>")
                f.close()
            
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("<tr><td style='width: 50%'><strong>Subtotal</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.subtotal), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Taxes</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.taxes), 'USD', locale='en_US') + "</td></tr>")
                f.write("<tr><td style='width: 50%'><strong>Total</strong></td><td style='width: 50%'>" + format_currency(str(found_invoice_values.total), 'USD', locale='en_US') + "</td></tr>")
                f.close()
            
                f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
                f.write("</table></table>")
                f.close() 
            f=open(app.config['UPLOAD_FOLDER'] + "/" +  name + ".html","a")
            f.write("<div id='footer_content' style='text-align: center;'>page <pdf:pagenumber> \
            of <pdf:pagecount> \
            </div> \
            </body> \
            </html>")
            
            
            f.close()
            
            OUTPUT_FILENAME = app.config['UPLOAD_FOLDER'] + "/" + name + ".pdf"
            TEMPLATE_FILE = app.config['UPLOAD_FOLDER'] + "/" + name + ".html"
            
            # Methods section ....
            def html_to_pdf(content, output):
            
                # Open file to write
                result_file = open(output, "w+b") # w+b to write in binary mode.

                # convert HTML to PDF
                pisa_status = pisa.CreatePDF(
                content,                   # the HTML to convert
                dest=result_file           # file handle to recieve result
                )           

                # close output file
                result_file.close()

                result = pisa_status.err

                if not result:
                    print("Successfully created PDF")
                else:
                    print("Error: unable to create the PDF")    

                # return False on success and True on errors
                return result



            def from_template(template, output):
   
                # Reading our template
                source_html = open(template, "r")
                content = source_html.read() # the HTML to convert
                source_html.close() # close template file

                html_to_pdf(content, output)
    
            from_template(TEMPLATE_FILE, OUTPUT_FILENAME)
            
            name=user_hashed
            name=name.replace("/","$$$") 
            name=name.replace(".","$$$")
            
            #INPUT_FILENAME = app.config['UPLOAD_FOLDER'] + "/" + name + ".pdf"
            #OUTPUT_TEMPLATE = '/iolcloud/' + name + ".pdf"
            
            access_token = app.config['DROPBOX_ACCESS_TOKEN']
            
            dbx = dropbox.Dropbox(access_token)
            found_template_data = db.session.query(TemplateData).filter_by(user_id=(user_hashed)).all()
            for row in found_template_data:
                
                TemplateData.query.delete()
                db.session.commit()
            
            
                
                
            transferData = TransferData(access_token)   
            file_from = app.config['UPLOAD_FOLDER'] + "/" + name + ".pdf" # This is name of the file to be uploaded
            file_to = "/iolcloud/" + name + ".pdf"  # This is the full path to upload the file to, including name that you wish the file to be called once uploaded.
            print(file_from)
            print(file_to)
            
            try:
                dbx.files_delete_v2("/iolcloud/" + name + ".pdf")
                transferData.upload_file(file_from, file_to)
            except:
                transferData.upload_file(file_from, file_to)
                
                    
            
            result = dbx.files_get_temporary_link(file_to)
            print(result.link)
            
            new_template = TemplateData(found_invoice_data.email, user_hashed, result.link)
            db.session.add(new_template)
            db.session.commit()           
            found_template_data = db.session.query(TemplateData).filter_by(user_id=(user_hashed)).first()
            
            return render_template('invoice-html.html', user=current_user, invoice_data=found_invoice_data, items_data=found_invoice_items, invoice_values=found_invoice_values, profile_data=found_profile_data, image_data=found_image_data, template_data=found_template_data, qrcode_data=found_qrcode_data)   
               
        
        else:
            return render_template('invoice-ein.html', user=current_user)
    except Exception as e:
        print(str(e))
        
    #return render_template('invoice.html')
    return 'Done'
    
   
@app.route('/_get_data_by_ein')
def get_by_ein():
    
    ein_result = request.args.get('ein')
    print(ein_result)

    result = db.session.query(InvoiceData).filter_by(ein = ein_result).first()
    invoicedata_schema	= InvoiceDataSchema()
   
    #result = Response(jsonpickle.encode(query1), mimetype='application/json')
    
    
    #print(result)
    output = invoicedata_schema.dump(result)
    
   
    
    #return jsonify({'invoiceaddress' : output})
    return jsonify(output)
    

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# check password complexity
def password_check(password):
    """
    Verify the strength of 'password'
    Returns a dict indicating the wrong criteria
    A password is considered strong if:
        8 characters length or more
        1 digit or more
        1 symbol or more
        1 uppercase letter or more
        1 lowercase letter or more
        credit to: ePi272314
        https://stackoverflow.com/questions/16709638/checking-the-strength-of-a-password-how-to-check-conditions
    """

    # calculating the length
    length_error = len(password) <= 8

    # searching for digits
    digit_error = re.search(r"\d", password) is None

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None

    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None

    # searching for symbols
    symbol_error = re.search(r"[ !@#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None

    ret = {
        'Password is less than 8 characters' : length_error,
        'Password does not contain a number' : digit_error,
        'Password does not contain a uppercase character' : uppercase_error,
        'Password does not contain a lowercase character' : lowercase_error,
        'Password does not contain a special character' : symbol_error,
    }

    return ret    
    
        
if __name__ == "__main__":
    app.run()

               
        
        
