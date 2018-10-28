###################################################################################################################
# "subprocess" added for shell commands support.  "time" added for progress bar support. "os" added for           #
# os.urandom function.  "listdir" and "isfile, join" added for /repo route.  "url_for"  added for file uploading. #
# "generate_password_hash" added to hash the password before storing into database.  "flask_login" added for      #
# login management.                                                                                               #
###################################################################################################################

from flask import Flask, render_template, request, redirect, send_from_directory, Response, flash, session, abort
from threading import Thread
import sqlite3 as sql
import subprocess
import time
import os
from os import listdir 
from os.path import isfile, join
from flask import url_for
from werkzeug import secure_filename
import re
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy

from flask import make_response
from functools import wraps, update_wrapper
from datetime import datetime

def nocache(view):
    @wraps(view)
    def no_cache(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Last-Modified'] = datetime.now()
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
        
    return update_wrapper(no_cache, view)


###############
# app configs #
###############

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////var/www/myapp/login.db'
app.config['SECRET_KEY'] = 'thisissecret'
app.secret_key = os.urandom(12)




#############################################
# basic initilizing of login management app #
#############################################

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)




#####################################
# Directory's variable for /uploader#
#####################################

CORE_BACKEND_DIR = '/var/www/myapp'
UPLOAD_FOLDER_BCF64_APPS = CORE_BACKEND_DIR + '/target/default_bcf_64/repo/apps'
UPLOAD_FOLDER_BCF64_MODS = CORE_BACKEND_DIR + '/target/default_bcf_64/repo/mods'

UPLOAD_FOLDER_SS32_APPS = CORE_BACKEND_DIR + '/target/softswitch32/repo/apps'
UPLOAD_FOLDER_SS32_MODS = CORE_BACKEND_DIR + '/target/softswitch32/repo/mods'
UPLOAD_FOLDER_SS32_EXTRA = CORE_BACKEND_DIR + '/target/softswitch32/repo/extra'

# I don't check the file extensions, if you would just uncomment
# below line and allowed_file function,
# also a line in /uploader definition.
#ALLOWED_EXTENSIONS = set(['txt'])
#def allowed_file(filename):
#    return '.' in filename and \
#	filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS



########################################
# Generating Apps for Softswitch 32bit #
########################################

@app.route('/upload_ss32')
@login_required
def upload_ss32():
    return render_template('upload_ss32.html')

   
@app.route("/uploader_ss32", methods=['GET', 'POST'])
@login_required
def index_ss32():
    if request.method == 'POST':
        file = request.files['file']
        if (file):
        #if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            if (re.match(r'Apps', filename)):
                app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER_SS32_APPS
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                return render_template('/upload_ok_ss32.html', filename = filename)
            
            elif (re.match(r'Mods', filename)):
                app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER_SS32_MODS
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                return render_template('/upload_ok_ss32.html', filename = filename)

            elif (re.match(r'Extra', filename)):
                app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER_SS32_EXTRA
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                return render_template('/upload_ok_ss32.html', filename = filename)

            else:
                return redirect("/home", code=302)
"""
@app.route("/download_ftp_ss32", methods=['GET','POST'])
def download_ftp_ss32():
    if request.method == 'POST':
        app_version = request.form['app_version']
        cmd = CORE_BACKEND_DIR + "/target/default_bcf_64/ftpmodule.py {0}".format(app_version)
        cmd_ftp_module = subprocess.check_output([cmd], shell=True)
        return redirect("/repo_bcf64", code=302)
"""
	
@app.route('/repo_ss32')
@login_required
def myrepo_ss32():
    apps_repo_path = CORE_BACKEND_DIR + "/target/softswitch32/repo/apps/"
    mods_repo_path = CORE_BACKEND_DIR + "/target/softswitch32/repo/mods/"
    extra_repo_path = CORE_BACKEND_DIR + "/target/softswitch32/repo/extra/"
    apps_repo_list = [f for f in listdir(apps_repo_path) if isfile(join(apps_repo_path, f))]
    mods_repo_list = [f for f in listdir(mods_repo_path) if isfile(join(mods_repo_path, f))]
    extra_repo_list = [f for f in listdir(extra_repo_path) if isfile(join(extra_repo_path, f))]
    apps_count = len(apps_repo_list)
    mods_count = len(mods_repo_list)
    ex_count = len(extra_repo_list)
    return render_template('repo_ss32.html', apps = apps_repo_list, mods = mods_repo_list, extra = extra_repo_list, apps_count = apps_count, mods_count = mods_count, ex_count = ex_count)

	
@app.route('/app_gen_ss32')
@login_required
def app_gen_ss32():
    apps_repo_path = CORE_BACKEND_DIR + "/target/softswitch32/repo/apps/"
    mods_repo_path = CORE_BACKEND_DIR + "/target/softswitch32/repo/mods/"
    extra_repo_path = CORE_BACKEND_DIR + "/target/softswitch32/repo/extra/"
    apps_repo_list = [f for f in listdir(apps_repo_path) if isfile(join(apps_repo_path, f))]
    mods_repo_list = [f for f in listdir(mods_repo_path) if isfile(join(mods_repo_path, f))]
    extra_repo_list = [f for f in listdir(extra_repo_path) if isfile(join(extra_repo_path, f))]
    return render_template('app_gen_ss32.html', apps = apps_repo_list, mods = mods_repo_list, extra = extra_repo_list)
	
	
@app.route('/app_gen_run_ss32', methods=['POST','GET'])
@login_required
def app_gen_run_ss32():
    if request.method == 'POST':
        serial = request.form['serial']
        app_ver = request.form['app_ver']
        app_ver_renamed_to_satisfy_below_script = re.sub( r'Apps-', '', app_ver)
	cmd = CORE_BACKEND_DIR + "/target/softswitch32/BuildApps {0} {1} ent2".format(app_ver_renamed_to_satisfy_below_script, serial)
        cmd_img_space = subprocess.check_output([cmd], shell=True)
        #return redirect("/home", code=302)
        return render_template("app_gen_success_ss32.html", serial = serial, app_ver = app_ver_renamed_to_satisfy_below_script)
		 

@app.route('/generated_apps/softswitch32/apps/<path:filename>', methods=['GET', 'POST'])
@login_required
def download_ss32_app(filename):
    return send_from_directory(directory='generated_apps/softswitch32/apps/', filename=filename)
	
	
@app.route('/def_gen_run_ss32', methods=['POST','GET'])
@login_required
def def_gen_run_ss32():
    if request.method == 'POST':
        serial = request.form['serial']
        app_ver = request.form['app_ver']
        app_ver_renamed_to_satisfy_below_script = re.sub( r'Apps-', '', app_ver)
        cmd = CORE_BACKEND_DIR + "/target/default_bcf_64/BuildDefault {0} ent2 {1}".format(serial, app_ver_renamed_to_satisfy_below_script)
        cmd_img_space = subprocess.check_output([cmd], shell=True)
        return render_template("default_bcf64_generated_successfully.html", serial = serial, app_ver = app_ver_renamed_to_satisfy_below_script)


@app.route('/generated_apps/softswitch32/defaults/<path:filename>', methods=['GET', 'POST'])
@login_required
def download_ss32_def(filename):
    return send_from_directory(directory='generated_apps/bcf64/defaults/', filename=filename)
	


# ###########################
# Generating App for BCF64 ##
# ###########################

@app.route('/upload_bcf64')
@login_required
def upload_file():
    return render_template('upload.html')

   
@app.route("/uploader_bcf64", methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        file = request.files['file']
        if (file):
        #if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            if (re.match(r'Apps', filename)):
                app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER_BCF64_APPS
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                return render_template('/upload_succeeded.html', filename = filename)
            
            if (re.match(r'Mods', filename)):
                app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER_BCF64_MODS
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                return render_template('/upload_succeeded.html', filename = filename)
            else:
                return redirect("/home", code=302)

	
@app.route("/download_ftp_bcf64", methods=['GET','POST'])
@login_required
def download_ftp_bcf64():
    if request.method == 'POST':
        app_version = request.form['app_version']
        cmd = CORE_BACKEND_DIR + "/target/default_bcf_64/ftpmodule.py {0}".format(app_version)
        cmd_ftp_module = subprocess.check_output([cmd], shell=True)
        return redirect("/repo_bcf64", code=302)

	
@app.route('/repo_bcf64')
@login_required
def myrepo():
    apps_repo_path = CORE_BACKEND_DIR + "/target/default_bcf_64/repo/apps/"
    mods_repo_path = CORE_BACKEND_DIR + "/target/default_bcf_64/repo/mods/"
    apps_repo_list = [f for f in listdir(apps_repo_path) if isfile(join(apps_repo_path, f))]
    mods_repo_list = [f for f in listdir(mods_repo_path) if isfile(join(mods_repo_path, f))]
    apps_count = len(apps_repo_list)
    mods_count = len(mods_repo_list)
    currentuser =  'profile ' + current_user.username
    return render_template('repo.html', apps = apps_repo_list, mods = mods_repo_list, apps_count = apps_count, mods_count = mods_count, currentuser = currentuser)

	
@app.route('/app_gen_bcf64')
@login_required
def app_gen():
    apps_repo_path = CORE_BACKEND_DIR + "/target/default_bcf_64/repo/apps/"
    mods_repo_path = CORE_BACKEND_DIR + "/target/default_bcf_64/repo/mods/"
    apps_repo_list = [f for f in listdir(apps_repo_path) if isfile(join(apps_repo_path, f))]
    mods_repo_list = [f for f in listdir(mods_repo_path) if isfile(join(mods_repo_path, f))]
    currentuser =  'profile ' + current_user.username
    return render_template('app_gen.html', apps = apps_repo_list, mods = mods_repo_list, currentuser = currentuser)
	
	
@app.route('/app_gen_run_bcf64', methods=['POST','GET'])
@login_required
def app_gen_run():
    if request.method == 'POST':
        serial = request.form['serial']
        app_ver = request.form['app_ver']
		 
        #I have used "re.sub" at below, sub is a method of re module, 
        #which searches and replaces the matched items for example 
	#re.sub(re'regex', 'replacewiththisone', string)
	 
        app_ver_renamed_to_satisfy_below_script = re.sub( r'Apps-', '', app_ver)
	cmd = CORE_BACKEND_DIR + "/target/default_bcf_64/BuildApps {0} {1} ent2".format(app_ver_renamed_to_satisfy_below_script, serial)
        cmd_img_space = subprocess.check_output([cmd], shell=True)
        #return redirect("/home", code=302)
        currentuser =  'profile ' + current_user.username
        return render_template("app_generated_successfully.html", serial = serial, app_ver = app_ver_renamed_to_satisfy_below_script, currentuser = currentuser)
		 

@app.route('/generated_apps/bcf64/apps/<path:filename>', methods=['GET', 'POST'])
@login_required
def download_bcf64_app(filename):
    return send_from_directory(directory='generated_apps/bcf64/apps/', filename=filename)
	
	
@app.route('/def_gen_run_bcf64', methods=['POST','GET'])
@login_required
def def_gen_run():
    if request.method == 'POST':
        serial = request.form['serial']
        app_ver = request.form['app_ver']
        app_ver_renamed_to_satisfy_below_script = re.sub( r'Apps-', '', app_ver)
        cmd = CORE_BACKEND_DIR + "/target/default_bcf_64/BuildDefault {0} ent2 {1}".format(serial, app_ver_renamed_to_satisfy_below_script)
        cmd_img_space = subprocess.check_output([cmd], shell=True)
        currentuser =  'profile ' + current_user.username
        return render_template("default_bcf64_generated_successfully.html", serial = serial, app_ver = app_ver_renamed_to_satisfy_below_script, currentuser = currentuser)


@app.route('/generated_apps/bcf64/defaults/<path:filename>', methods=['GET', 'POST'])
@login_required
def download_bcf64_def(filename):
    return send_from_directory(directory='generated_apps/bcf64/defaults/', filename=filename)
	



#######################
# Application64 page #
#######################

@app.route('/applications64')
@login_required
def applications64():
    currentuser =  'profile ' + current_user.username
    return render_template("applications64.html", currentuser = currentuser)




######################
# Application32 Page #
######################

@app.route('/applications32')
@login_required
def applications32():
    currentuser =  'profile ' + current_user.username
    return render_template("applications32.html", currentuser = currentuser)




#################################
# Generate app from GitLab AGCF #
#################################
'''
@app.route('/app_gitlab')
@login_required
def app_gitlab():
    currentuser =  'profile ' + current_user.username
    return render_template("app_gitlab.html", currentuser = currentuser)
'''

@app.route('/gitlab_gen')
@login_required
def agcf_git():
    apps_repo_path = CORE_BACKEND_DIR + "/gitlab_gen/repo/apps/"
    mods_repo_path = CORE_BACKEND_DIR + "/gitlab_gen/repo/mods/"
    extra_repo_path = CORE_BACKEND_DIR + "/gitlab_gen/repo/extra/"
    apps_repo_list = [f for f in listdir(apps_repo_path) if isfile(join(apps_repo_path, f))]
    mods_repo_list = [f for f in listdir(mods_repo_path) if isfile(join(mods_repo_path, f))]
    extra_repo_list = [f for f in listdir(extra_repo_path) if isfile(join(extra_repo_path, f))]
    apps_count = len(apps_repo_list)
    mods_count = len(mods_repo_list)
    ex_count = len(extra_repo_list)
    currentuser =  'profile ' + current_user.username
    return render_template('gitlab_gen.html', apps = apps_repo_list, mods = mods_repo_list, extra = extra_repo_list, apps_count = apps_count, mods_count = mods_count, ex_count = ex_count, currentuser = currentuser)



@app.route('/gitlab_repo_apps/<path:filename>', methods=['GET', 'POST'])
@login_required
def download_apps(filename):
    return send_from_directory(directory='gitlab_gen/repo/apps/', filename=filename)


@app.route('/gitlab_repo_mods/<path:filename>', methods=['GET', 'POST'])
@login_required
def download_mods(filename):
    return send_from_directory(directory='gitlab_gen/repo/mods/', filename=filename)


@app.route('/gitlab_repo_extra/<path:filename>', methods=['GET', 'POST'])
@login_required
def download_extra(filename):
    return send_from_directory(directory='gitlab_gen/repo/extra/', filename=filename)



@app.route("/agcf_git_gen", methods=['GET','POST'])
@login_required
@nocache
def agcf_git_gen():
    if request.method == 'POST':
        typ = request.form['type']
        serial = request.form['serial']
        url = request.form['url']
        unit = request.form['unit']
        git_user = request.form['git_user']
        git_pass = request.form['git_pass']
        git_branch = request.form['git_branch']
        git_model = request.form['git_model']
        currentuser =  current_user.username
        cmd = CORE_BACKEND_DIR + "/gitlab_gen/git_gen {0} {1} {2} {3} {4} '{5}' {6} {7} {8}>> ./logs/gitlab_generate.log".format(typ, serial, url, unit, git_user, git_pass, git_branch, currentuser, git_model)

        script_output = subprocess.check_output([cmd], shell=True)
        output = script_output.splitlines()
        with open('./logs/gitlab_generate.log', 'r') as logfile:
            lines = logfile.read().splitlines()
            last_line = lines[-1]
            print last_line

        if 'Error' in last_line:
            return render_template("gitlab_result_error.html")
        else:
            return redirect("/gitlab_gen", code=302)

        #cmd_ftp_module = subprocess.check_output([cmd], shell=True)
        #return redirect("/gitlab_gen", code=302)




# ####################
#      Home page     #
# #################### 

@app.route('/home')
@login_required
def home():
    con = sql.connect("database.db")
    con.row_factory = sql.Row
    cur = con.cursor()
    cur.execute("select * from os")
    rows = cur.fetchall();
    total_images = len(rows)
    con.close()
    cmd = "du -h images/ | awk '{print $1}'"
    cmd_img_space = subprocess.check_output([cmd], shell=True)
    currentuser = 'profile ' + current_user.username
    client_ip_address = request.environ['REMOTE_ADDR']
    return render_template('home.html', total_images = total_images, space = cmd_img_space, currentuser = currentuser, ip = client_ip_address)




######################################
# creating User login for the system #
######################################

@app.route('/users')
@login_required
def users():
    currentuser = 'profile ' + current_user.username
    return render_template('user_register.html', currentuser = currentuser)

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    try:
        username =  request.form['username']
        #role = request.form['role']
        password = request.form['password'] 
        user = User.query.filter_by(username=username).first()
        if user is None:
            u = User(username=username)
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            msg = 'User {0} added successfully ;)'.format(username)
            return render_template('user_add_result.html', msg = msg)
        else:
            msg = 'User {0} exist, please try another name!'.format(username)
            return render_template('user_add_result.html', msg = msg)
 
    except SQLAlchemyError as err:
        print 'Oops!  There is a problem here: {0}'.format(err)




######################
# user settings page #
######################

@app.route('/user_settings')
@login_required
def user_settings():
    currentuser =  current_user.username
    return render_template('user_settings.html', currentuser = currentuser)

@app.route('/change_user_settings', methods=['POST'])
@login_required
def change_user_settings():
    username =  request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user is not None:
        u = User.query.filter_by(username=username).first()
        u.set_password(password)
        db.session.commit()
        msg = 'Password for user {0} successfully changed ;)'.format(username)
        return render_template('user_add_result.html', msg = msg)
    else:
        msg = 'User {0} not found ;)'.format(username)
        return render_template('user_settings_result.html', msg = msg)
	  


 
# ###############################
# Download and Delete an Image  #
# ###############################

@app.route('/images/<path:filename>', methods=['GET', 'POST'])
@login_required
def download(filename):
    return send_from_directory(directory='images', filename=filename)


@app.route('/confirm/<path:serial>', methods=['GET'])
@login_required
def delete_confirm(serial):
    return render_template('delete.html', serial = serial)


@app.route('/img_rm/<path:serial>', methods=['GET'])
@login_required
def delete_entry(serial):
    with sql.connect("database.db") as con:
        cur = con.cursor()
        cur.execute('delete from os where serial = ?', (serial,))
        con.commit()
        cmd = "rm  /var/www/myapp/images/{0}".format(serial)
        cmd_output = subprocess.check_output([cmd], shell=True)
        return redirect("/list", code=302)




			
# ##########################################
# Register a Serial and Generate the image #	
#  and the list the images                 #
# ##########################################
	
@app.route('/enternew')
@login_required
def new_student():
    con = sql.connect("database.db")
    con.row_factory = sql.Row
    cur = con.cursor()
    cur.execute("select * from hw")
    rows = cur.fetchall();
    currentuser =  'profile ' + current_user.username
    return render_template("register_os.html", rows = rows, currentuser = currentuser)
    con.close()   

	   
@app.route('/addrec',methods = ['POST', 'GET'])
@login_required
def addrec():
    if request.method == 'POST':
        try:
            serial = request.form['serial']
            serial = serial.replace(" ", "")
            date = request.form['date']
            owner = request.form['owner']
            type1 = request.form['type']
            type1 = type1.replace(" ", "")
            hardware = request.form['hardware']
            description = request.form['description']
            with sql.connect("database.db") as con:
               cur = con.cursor()
               cur.execute('SELECT * FROM os where serial = ?', (serial,))
               rows = cur.fetchall();
               print rows
               if (rows):
                   return render_template("result.html", serial = serial)
                   con.close()
               else:
                   cur.execute("INSERT INTO os (serial,date,owner,type,hardware) VALUES (?,?,?,?,?)",(serial,date,owner,type1,hardware))
                   cur.execute("INSERT INTO report (serial,date,owner,type,hardware,description) VALUES (?,?,?,?,?,?)",(serial,date,owner,type1,hardware,description))
                   con.commit()
                   def run_installer():
                       cmd = "/var/www/myapp/target/BCF_FILES_FOR_NEW_ENC/00/installer -s {0}".format(serial)
                       cmd_output = subprocess.check_output([cmd], shell=True)
                   t = Thread(target=run_installer, args=())
                   t.start()
                   return render_template("generating.html", serial = serial)
                   con.close()
        except:
            con.rollback()

			
@app.route('/list')
@login_required
def list():
    con = sql.connect("database.db")
    con.row_factory = sql.Row
    cur = con.cursor()
    cur.execute("select * from os ORDER BY id DESC LIMIT 1000")
    rows = cur.fetchall();
    total_images = len(rows)
    currentuser =  'profile ' + current_user.username
    return render_template("list.html",rows = rows, total_images = total_images, currentuser = currentuser)
    con.close()

	   
	   
	   
# #############################
# Report of registered images #
# #############################
	   
@app.route('/report')
@login_required
def report():
    con = sql.connect("database.db")
    con.row_factory = sql.Row
    cur = con.cursor()
    cur.execute("select * from report ORDER BY id DESC LIMIT 1000")
    rows = cur.fetchall();
    total_images = len(rows)
    currentuser =  'profile ' + current_user.username
    return render_template("report.html",rows = rows, total_images = total_images, currentuser = currentuser)
    con.close()



	   
# ######################################
#  Related to Hardware's section which #
# you add a new hardware, Delete and   #
# lists them.                          #
# ######################################

@app.route('/hw_list')
@login_required
def hw_list():
    con = sql.connect("database.db")
    con.row_factory = sql.Row
    cur = con.cursor()
    cur.execute("select * from hw")
    rows = cur.fetchall();
    total_hw_sets = len(rows)
    currentuser =  'profile ' + current_user.username
    return render_template("hw_list.html", rows = rows, total_hw_sets = total_hw_sets, currentuser = currentuser)
    con.close()    


@app.route('/hw_enter')
@login_required
def hw_enter():
    currentuser =  'profile ' + current_user.username    
    return render_template('hw_enter.html', currentuser = currentuser)


@app.route('/hw_add',methods = ['POST', 'GET'])
@login_required
def hw_add():
    if request.method == 'POST':
        try:
            model = request.form['model']
            cpu = request.form['cpu']
            ram = request.form['ram']
            storage1 = request.form['storage1']
            storage2 = request.form['storage2']
            with sql.connect("database.db") as con:
                cur = con.cursor()
                cur.execute("INSERT INTO hw (model,cpu,ram,storage1,storage2) VALUES (?,?,?,?,?)",(model,cpu,ram,storage1,storage2) )
                con.commit()
                msg = "New Hardware successfully added."
                return render_template("hw_add_result.html", msg = msg)
                con.close()
        except:
            con.rollback()
            print "error in insert operation"

			
@app.route('/hw_confirm/<path:id>')
@login_required
def show_hw_confirm(id):
    return render_template('hw_delete_confirm.html', id = id)


@app.route('/hw/<path:id>', methods=['GET'])
@login_required
def delete_hw(id):
    with sql.connect("database.db") as con:
        cur = con.cursor()
        cur.execute('delete from hw where id = ?', (id,))
        con.commit()
        return redirect("/hw_list", code=302)



				
# #############################################
# search is added to registered OS section to #
# look for and filter base on serial numbers, #
# date, owner, type                           #
# #############################################

@app.route('/search',methods = ['POST', 'GET'])
@login_required
def search():
    if request.method == 'POST':
        search_value = request.form['search']
        search_value = search_value.upper().replace(" ", "").replace("'", "")
        if (search_value):
            con = sql.connect("database.db")
            con.row_factory = sql.Row
            cur = con.cursor()
            cur.execute("SELECT * FROM os WHERE serial LIKE ? COLLATE NOCASE ORDER BY date DESC", ('%{}%'.format(search_value),))
            rows = cur.fetchall();
            total_images = len(rows)
            if (rows):
                return render_template("list.html",rows = rows, total_images = total_images)
                con.close()
            else:
                cur.execute("SELECT * FROM os WHERE date='%s' COLLATE NOCASE ORDER BY date DESC" % (search_value,))
                rows = cur.fetchall();
                total_images = len(rows)
                if (rows):
                    return render_template("list.html",rows = rows, total_images = total_images)
                    con.close()
                else:
                    cur.execute("SELECT * FROM os WHERE owner LIKE ? COLLATE NOCASE ORDER BY date DESC", ('%{}%'.format(search_value),))
                    rows = cur.fetchall();
                    total_images = len(rows)
                    if (rows):
                        return render_template("list.html",rows = rows, total_images = total_images)
                    else:
                        cur.execute("SELECT * FROM os WHERE type='%s' COLLATE NOCASE ORDER BY date DESC" % (search_value,))
                        rows = cur.fetchall();
                        total_images = len(rows)
                        if (rows):
                            return render_template("list.html",rows = rows, total_images = total_images)
                            con.close()
                        else:
                            return render_template('notfound.html')
        else:
                 return render_template('notfound.html')




# ########################################
# search functionality in Report section #
# ########################################

@app.route('/search_for_report',methods = ['POST', 'GET'])
@login_required
def search_for_report():
    if request.method == 'POST':
        search_value = request.form['search']
        search_value = search_value.upper().replace(" ", "").replace("'", "")
        search_value = search_value.decode('ascii', 'ignore')
        if (search_value):
            con = sql.connect("database.db")
            con.row_factory = sql.Row
            cur = con.cursor()
            cur.execute("SELECT * FROM report WHERE serial LIKE ? COLLATE NOCASE ORDER BY date DESC", ('%{}%'.format(search_value),))
            rows = cur.fetchall();
            total_images = len(rows)
            if (rows):
                return render_template("report.html",rows = rows, total_images = total_images)
                con.close()
            else:
                cur.execute("SELECT * FROM report WHERE date='%s' COLLATE NOCASE ORDER BY date DESC" % (search_value,))
                rows = cur.fetchall();
                total_images = len(rows)
                if (rows):
                    return render_template("report.html",rows = rows, total_images = total_images)
                    con.close()
                else:
                    cur.execute("SELECT * FROM report WHERE owner LIKE ? COLLATE NOCASE ORDER BY date DESC", ('%{}%'.format(search_value),))
                    rows = cur.fetchall();
                    total_images = len(rows)
                    if (rows):
                        return render_template("report.html",rows = rows, total_images = total_images)
                    else:
                        cur.execute("SELECT * FROM report WHERE type='%s' COLLATE NOCASE ORDER BY date DESC" % (search_value,))
                        rows = cur.fetchall();
                        total_images = len(rows)
                        if (rows):
                            return render_template("report.html",rows = rows, total_images = total_images)
                            con.close()
                        else:
                            cur.execute("SELECT * FROM report WHERE description LIKE ? COLLATE NOCASE ORDER BY date DESC", ('%{}%'.format(search_value),))
                            rows = cur.fetchall();
                            total_images = len(rows)
                            if (rows):
                                return render_template("report.html",rows = rows, total_images = total_images)
                            else:
                                return render_template('notfound.html')
        else:
           return render_template('notfound.html')


				 				 
				 
# ###########################################################################				 
# progress sends event to javascript, check out "generate.html" file,       #
#this is a sample to increases the progress bar 1 percent each 1 second.    #
# ###########################################################################

@app.route('/progress')
@login_required
def progress():
    def generate():
        x = 0
        while x <= 100:
            yield "data:" + str(x) + "\n\n"
            x = x + 1
            if (x==40):
                time.sleep(10)
            elif (x==80):
                time.sleep(10)
            else:
                time.sleep(1)
    return Response(generate(), mimetype= 'text/event-stream')

		
		
		
# ############################
# Added for login management #
# ############################
'''
@app.route('/')
def login():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return redirect("/home", code=302)


@app.route('/login', methods=['POST'])
def do_admin_login():
    if request.form['password'] == 'pass' and request.form['username'] == 'admin':
        session['logged_in'] = True
    else:
        flash('wrong password!')
    return login()

@app.route("/logout")
def logout():
    session['logged_in'] = False
    return login()
'''

##################################################
# Using User objects you can add a user          #
# and using set_password method you generate     #
# hash from your password befofore storing       #
# into the databse, also using check_password    #
# method you can check the user entered password #
# with database and it returns true or false.    #
##################################################

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)



#################################################
# keeps track of the logged in user by storing  #
# its unique identifier in Flask's user session #
#################################################

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



#############################################
# View functions for users login management #
#############################################

@app.route('/')
def root():
    if current_user.is_authenticated():
        return redirect('/home', code=302)
    else:
        return render_template('/login.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user is None or not user.check_password(password):
        msg = "Check your username and password then try again!"
        return render_template('/login.html', msg=msg)
    else:
        login_user(user)
        return redirect('/home')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    msg = "You have logged out."
    return render_template('/login.html', msg = msg)



##################
# error 401 page #
##################

@app.errorhandler(401)
def custom_401(error):
    msg = 'You do not have access to that page without login! '
    return render_template('/login.html', msg = msg)




##################
# error 404 page #
##################

@app.errorhandler(404)
def custom_404(error):
    return render_template('notfound.html')
	
	
	
if __name__ == '__main__':
    app.run(debug=True, host='192.168.88.166', port=5000, threaded=True)

