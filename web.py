from flask import Flask, flash, jsonify, redirect, request, url_for, render_template
from flask_mongoengine import MongoEngine
from wtforms import form, fields, validators
from flask_admin import AdminIndexView, Admin, expose, BaseView
from flask_admin.menu import MenuLink
from flask_admin.babel import gettext
from flask_admin.contrib.mongoengine import ModelView
from flask_login import LoginManager,current_user,login_user,logout_user
from flask_bcrypt import Bcrypt
from werkzeug.exceptions import HTTPException
from werkzeug import secure_filename
from uuid import uuid4
from tempfile import gettempdir
from os import path, getpid
from datetime import datetime
from os import path
from flask_wtf.csrf import CSRFProtect
from requests import get
from flaskext.markdown import Markdown
from pymongo import MongoClient
from platform import platform as pplatform
from psutil import cpu_percent, virtual_memory, Process
from shutil import disk_usage
from settings import json_settings, mongodb_settings
from wtforms import SelectMultipleField
from wtforms.widgets import ListWidget, CheckboxInput
from bson.objectid import ObjectId
from json import JSONEncoder, dumps

filename = "README.md"
intromarkdown = ""

try:
    r = get('https://raw.githubusercontent.com/qeeqbox/analyzer/master/README.md')
    if r.text != "" and r.ok:
        intromarkdown = r.text
except:
    pass

if intromarkdown == "":
    try:
        readmefolder = path.abspath(path.join(path.dirname( __file__ ),filename))
        with open(readmefolder) as f:
            intromarkdown = f.read()
    except:
        intromarkdown = ""

switches = [('full','full'),('behavior','behavior'),('xref','xref'),('yara','yara'),('language','language'),('mitre','mitre'),('topurl','topurl'),('ocr','ocr'),('enc','enc'),('cards','cards'),('creds','creds'),('patterns','patterns'),('suspicious','suspicious'),('dga','dga'),('plugins','plugins'),('visualize','visualize'),('flags','flags'),('icons','icons'),('worldmap','worldmap'),('spelling','spelling'),('image','image'),('phishing','phishing'),('unicode','unicode'),('bigfile','bigfile'),('w_internal','w_internal'),('w_original','w_original'),('w_hash','w_hash'),('w_words','w_words'),('w_all','w_all'),('ms_all','ms_all')]

app = Flask(__name__)
app.secret_key = "63c98a9cd54036c4a1505357ba1b5d4af5bbdfa26c477a43bc23ee9ed88fb874673b1fde50026533b6f9a41cfa0cd98c1132a0c8961a8432de708b193aaf979c"
#app.secret_key = uuid4().hex fix workers

conn = MongoClient(json_settings["mongo_settings_docker"])
app.config['MONGODB_SETTINGS'] = mongodb_settings
db = MongoEngine()
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.setup_app(app)
csrf = CSRFProtect()
csrf.init_app(app)
Markdown(app)

def find_items(db,col,items):
    _dict = {}
    for item in items:
        if item != '':
            ret = conn[db][col].find_one({"_id":ObjectId(item)},{'_id': False})
            if ret != None:
                _dict.update({item:ret})
    return _dict

def convert_size(s):
    for u in ['B','KB','MB','GB']:
        if s < 1024.0:
            return "{:.2f}{}".format(s,u)
        else:
            s /= 1024.0
    return "File is too big"

class Namespace:
    def __init__(self, kwargs):
        self.__dict__.update(kwargs)

@login_manager.user_loader
def load_user(user_id):
    return User.objects(id=user_id).first()

class User(db.Document):
    login = db.StringField(max_length=80, unique=True)
    password = db.StringField(max_length=64)
    meta = {'db_alias':'default','collection': 'users','strict': False}

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def __unicode__(self):
        return self.login

class UserView(ModelView):
    can_create = False
    can_delete = True
    can_edit = False

    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        if not self.is_accessible():
            return redirect(url_for('admin.login_view', next=request.url))

class Jobs(db.Document):
    jobID = db.StringField()
    status = db.StringField()
    created = db.DateTimeField()
    started = db.DateTimeField()
    finished = db.DateTimeField()
    data = db.DictField()
    meta = {"db_alias": "jobsqueue",'strict': False}

class QueueView(ModelView):
    list_template = 'list.html'
    can_create = False
    can_delete = False
    can_edit = True
    column_searchable_list = ['jobID']
    extra_js = ['/static/jobs_style.js ']

    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        if not self.is_accessible():
            return redirect(url_for('admin.login_view', next=request.url))

class Files(db.Document):
    uuid = db.StringField()
    line = db.DictField()
    file = db.FileField()
    meta = {'db_alias':'default','collection': 'files','strict': False}

class FilesView(ModelView):
    can_create = False
    can_delete = True
    can_edit = False
    column_searchable_list = ['uuid']

    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        if not self.is_accessible():
            return redirect(url_for('admin.login_view', next=request.url))

class Reports(db.Document):
    uuid = db.StringField()
    type = db.StringField()
    file = db.FileField()
    time = db.DateTimeField()
    meta = {'db_alias':'default','collection': 'reports','strict': False}

class ReportsView(ModelView):
    can_create = False
    can_delete = True
    can_edit = False
    column_searchable_list = ['uuid']
    column_default_sort = ('time', True)

    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        if not self.is_accessible():
            return redirect(url_for('admin.login_view', next=request.url))

class Logs(db.Document):
    uuid = db.StringField()
    type = db.StringField()
    file = db.FileField()
    time = db.DateTimeField()
    meta = {'db_alias':'default','collection': 'logs','strict': False}

class LogsView(ModelView):
    can_create = False
    can_delete = True
    can_edit = False
    column_searchable_list = ['uuid']
    column_default_sort = ('time', True)

    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        if not self.is_accessible():
            return redirect(url_for('admin.login_view', next=request.url))

class LoginForm(form.Form):
    login = fields.StringField(render_kw={"placeholder": "Username"})
    password = fields.PasswordField(render_kw={"placeholder": "Password"})

    def validate_login(self, field):
        user = self.get_user()  #fix AttributeError: 'NoneType' object has no attribute 'password'
        if user != None:
            if not bcrypt.check_password_hash(user.password,self.password.data):
                raise validators.ValidationError('Invalid password')

    def get_user(self):
        return User.objects(login=self.login.data).first()

class RegistrationForm(form.Form):
    login = fields.StringField(render_kw={"placeholder": "Username"})
    password = fields.PasswordField(render_kw={"placeholder": "Password"})

    def validate_login(self, field):
        if User.objects(login=self.login.data):
            raise validators.ValidationError('Duplicate username')

class CustomAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not current_user.is_authenticated:
            return redirect(url_for('.login_view'))
        self._template_args['filename'] = filename + " @ https://github.com/qeeqbox/analyzer"
        self._template_args['intro'] = intromarkdown
        return super(CustomAdminIndexView, self).index()

    @expose('/login/', methods=['POST','GET'])
    def login_view(self):
        # handle user login
        form = LoginForm(request.form)
        if request.method == 'POST' and form.validate():
            user = form.get_user()
            if user != None:
                login_user(user)

        if current_user.is_authenticated:
            return redirect(request.args.get('next') or url_for('.index'))

        self._template_args['form'] = form
        self._template_args['active'] = "Login"
        self._template_args['intro'] = ""
        self._template_args['link'] = '<p>Register? <a href="{}">Click here</a></p>'.format(url_for('.register_view'))
        return super(CustomAdminIndexView, self).index()

    @expose('/register/', methods=('GET', 'POST'))
    def register_view(self):
        form = RegistrationForm(request.form)
        if request.method == 'POST' and form.validate():
            user = User()
            form.populate_obj(user)
            user["password"] = bcrypt.generate_password_hash(user["password"]).decode('utf-8')
            user.save()
            login_user(user)
            return redirect(url_for('.index'))

        self._template_args['form'] = form
        self._template_args['active'] = "Register"
        self._template_args['intro'] = ""
        self._template_args['link'] = '*Please do not enter a used username or password<p><p>Login? <a href="{}">Click here</a></p>'.format(url_for('.login_view'))
        return super(CustomAdminIndexView, self).index()

    @expose('/logout/')
    def logout_view(self):
        logout_user()
        return redirect(url_for('.index'))

    def is_visible(self):
        return False

class MultiCheckboxField(SelectMultipleField):
    widget          = ListWidget(prefix_label=False)
    option_widget   = CheckboxInput()

class UploadForm(form.Form):
    choices = MultiCheckboxField('Assigned', choices=switches)
    file = fields.FileField(render_kw={"multiple": True})
    analyzertimeout = fields.SelectField('analyzertimeout',choices=[(30, '30sec'), (60, '1min'), (120, '2min')],default=(json_settings["analyzer_timeout"]),coerce=int)
    functiontimeout = fields.SelectField('functiontimeout',choices=[(10, '10sec'), (20, '20sec'), (30, '30sec'), (40, '40sec'), (50, '50sec'), (60, '60sec'),(100,'1:40min')],default=(json_settings["function_timeout"]),coerce=int)
    submit = fields.SubmitField(render_kw={"class":"btn"}) 
    __order = ('file', 'choices', 'analyzertimeout','functiontimeout','submit')
    def __iter__(self):
        fields = list(super(UploadForm, self).__iter__())
        get_field = lambda fid: next((f for f in fields if f.id == fid))
        return (get_field(fid) for fid in self.__order)

class CustomViewUploadForm(BaseView):
    @expose('/', methods=['POST','GET'])

    def index(self):
        # handle user login
        form = UploadForm(request.form)
        if request.method == 'POST':
            uploaded_files = request.files.getlist("file")
            for file in uploaded_files:
                filename = ""
                uuid = str(uuid4())
                if file:
                    result = {}
                    filename = secure_filename(file.filename)
                    savetotemp = path.join(gettempdir(),filename)
                    for x in request.form.getlist("choices"):
                        result.update({x:True})
                    result["file"] = savetotemp
                    result["uuid"] = uuid
                    result["analyzer_timeout"]= form.analyzertimeout.data
                    result["function_timeout"]= form.functiontimeout.data
                    files = Files()
                    files.uuid = uuid
                    files.line = result
                    #form.populate_obj(files)
                    #save to db
                    files.file.put(file, content_type=file.content_type, filename=filename)
                    files.save()
                    #save to hdd
                    file.seek(0)
                    file.save(savetotemp)
                    #q_return = queue.insert(uuid,result)
                    jobs = Jobs()
                    jobs.jobID = uuid
                    jobs.status = 'wait'
                    jobs.created = datetime.now()
                    jobs.started = datetime.now()
                    jobs.finished = datetime.now()
                    jobs.data = result
                    jobs.save()
                    flash(gettext("Done uploading {} Task ({})".format(filename,uuid)), 'success')
                else:
                    flash(gettext("Something wrong while uploading {} Task ({})".format(filename,uuid)), 'error')
        return self.render("fileupload.html",form=form)

    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        if not self.is_accessible():
            return redirect(url_for('admin.login_view', next=request.url))

class BufferForm(form.Form):
    choices = MultiCheckboxField('Assigned', choices=switches)
    buffer = fields.TextAreaField(render_kw={"class": "buffer"})
    analyzertimeout = fields.SelectField('analyzertimeout',choices=[(30, '30sec'), (60, '1min'), (120, '2min')],default=int(json_settings["analyzer_timeout"]),coerce=int)
    functiontimeout = fields.SelectField('functiontimeout',choices=[(10, '10sec'), (20, '20sec'), (30, '30sec'), (40, '40sec'), (50, '50sec'), (60, '60sec'),(100,'1:40min')],default=int(json_settings["function_timeout"]),coerce=int)
    submit = fields.SubmitField(render_kw={"class":"btn"})
    __order = ('buffer', 'choices', 'analyzertimeout','functiontimeout','submit')
    def __iter__(self):
        fields = list(super(BufferForm, self).__iter__())
        get_field = lambda fid: next((f for f in fields if f.id == fid))
        return (get_field(fid) for fid in self.__order)

class CustomViewBufferForm(BaseView):
    @expose('/', methods=['POST','GET'])
    def index(self):
        form = BufferForm(request.form)
        if request.method == 'POST':
            if form.buffer.data != "":
                uuid = str(uuid4())
                result = {}
                for x in request.form.getlist("choices"):
                    result.update({x:True})
                result["uuid"] = uuid
                result["buffer"] = form.buffer.data
                result["analyzer_timeout"]= form.analyzertimeout.data
                result["function_timeout"]= form.functiontimeout.data
                jobs = Jobs()
                jobs.jobID = uuid
                jobs.status = 'wait'
                jobs.created = datetime.now()
                jobs.started = datetime.now()
                jobs.finished = datetime.now()
                jobs.data = result
                jobs.save()
                flash(gettext("Done submitting buffer Task ({})".format(uuid)), 'success')
            else:
                flash(gettext("Something wrong"), 'error')
        return self.render("bufferupload.html",form=form)

    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        if not self.is_accessible():
            return redirect(url_for('admin.login_view', next=request.url))

def get_stats():
    #lazy check stats
    stats = {}
    try:
        coll = "jobs"
        if coll in conn["jobsqueue"].list_collection_names():
            stats.update({"[{}] Collection".format(coll):"Exists"})
        else:
            stats.update({"[{}] Collection".format(coll):"Does not exists"})
    except:
        pass
    try:
        for coll in ("reports","files","fs.chunks","fs.files"):
            if coll in conn["webinterface"].list_collection_names():
                stats.update({"[{}] Collection".format(coll):"Exists"})
            else:
                stats.update({"[{}] Collection".format(coll):"Does not exists"})
    except:
        pass
    try:
        db = "jobsqueue" 
        col = "jobs"
        stats.update({  "[Queue] status":True if conn[db][col].find_one({'status': 'ON__'},{'_id': False}) else False,
                        "[Queue] Total jobs ": conn[db][col].find({"status" : {"$nin" : ["ON__","OFF_"]}}).count(),
                        "[Queue] Total finished jobs":conn[db][col].find({'status': 'done'}).count(),
                        "[Queue] Total waiting jobs":conn[db][col].find({'status': 'wait'}).count()})
                        
    #get total disk usage
    #"[Queue] Used space":"{} of {}".format(convert_size(conn[db].command("dbstats")["fsUsedSize"]),convert_size(conn[db].command("dbstats")["fsTotalSize"]))

    except:
        pass
    try:
        db = "webinterface" 
        col = "reports"
        stats.update({"[Reports] Total reports":conn[db][col].find({}).count(),
                      "[Reports] Total used space":"{}".format(convert_size(conn[db].command("collstats",col)["storageSize"] + conn[db].command("collstats",col)["totalIndexSize"]))})
    except:
        pass
    try:
        db = "webinterface" 
        col = "files"
        stats.update({"[Files] Total files uploaded":conn[db][col].find({}).count()})
    except:
        pass
    try:
        db = "webinterface" 
        col = "fs.chunks"
        stats.update({"[Files] Total uploaded files size":"{}".format(convert_size(conn[db][col].find().count() * 255 * 1000))})
    except:
        pass
    try:
        db = "webinterface" 
        col = "users"
        stats.update({"[Users] Total users":conn[db][col].find({}).count()})
    except:
        pass
    try:
        total, used, free = disk_usage("/")
        stats.update({"CPU memory":cpu_percent(),
                      "Memory used":virtual_memory()[2],
                      "Current process used memory": "{}".format(convert_size(Process(getpid()).memory_info().rss)),
                      "Total disk size": "{}".format(convert_size(total)),
                      "Used disk size": "{}".format(convert_size(used)),
                      "Free disk size": "{}".format(convert_size(free)),
                      "Host platform":pplatform()})
    except:
        pass

    conn.close()
    return stats

class CustomStatsView(BaseView):
    @expose('/', methods=['GET'])
    def index(self):
        return self.render("stats.html", stats = get_stats())

    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        if not self.is_accessible():
            return redirect(url_for('admin.login_view', next=request.url))

class TimeEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.astimezone().strftime("%Y-%m-%d %H:%M:%S.%f")
        return JSONEncoder.default(self, obj)

class CustomDBupdate(BaseView):
    @expose('/', methods=['POST'])
    def index(self):
        if request.json:
            json_content = request.get_json(silent=True)
            items = find_items("jobsqueue","jobs",json_content)
            if items != None:
                return dumps(items, cls=TimeEncoder)
        else:
            return jsonify({"Error":"Something wrong"})

    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        if not self.is_accessible():
            return redirect(url_for('admin.login_view', next=request.url))
    
    def is_visible(self):
        return False

class CustomMenuLink(MenuLink):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        if not self.is_accessible():
            return redirect(url_for('admin.login_view', next=request.url))

class StarProject(MenuLink):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        if not self.is_accessible():
            return redirect(url_for('admin.login_view', next=request.url))
 
def error_handler(error):
    return render_template("error.html",error=url_for('admin.index'),uuid=str(uuid4()))

for cls in HTTPException.__subclasses__():
    app.register_error_handler(cls, error_handler)

admin = Admin(app, "QB" , index_view=CustomAdminIndexView(url='/'),base_template='base.html' , template_mode='bootstrap3')
admin.add_link(CustomMenuLink(name='', category='', url="https://github.com/qeeqbox/analyzer", icon_type='glyph', icon_value='glyphicon-star'))
admin.add_link(CustomMenuLink(name='', category='', url="https://github.com/qeeqbox/analyzer/archive/master.zip", icon_type='glyph', icon_value='glyphicon-download-alt'))
admin.add_link(CustomMenuLink(name='', category='', url="https://github.com/qeeqbox/analyzer/subscription", icon_type='glyph', icon_value='glyphicon glyphicon-eye-open'))
admin.add_link(CustomMenuLink(name='Logout', category='', url="/logout", icon_type='glyph', icon_value='glyphicon glyphicon-user'))
admin.add_view(CustomStatsView(name="Stats",endpoint='stats',menu_icon_type='glyph', menu_icon_value='glyphicon-stats'))
admin.add_view(CustomDBupdate(name="DBinfo",endpoint='dbinfo',menu_icon_type='glyph', menu_icon_value='glyphicon-stats'))
admin.add_view(CustomViewBufferForm(name="Buffer",endpoint='buffer',menu_icon_type='glyph', menu_icon_value='glyphicon-edit'))
admin.add_view(CustomViewUploadForm(name="Upload",endpoint='upload',menu_icon_type='glyph', menu_icon_value='glyphicon-upload'))
admin.add_view(UserView(User, menu_icon_type='glyph', menu_icon_value='glyphicon-user'))
admin.add_view(FilesView(Files,menu_icon_type='glyph', menu_icon_value='glyphicon-file'))
admin.add_view(QueueView(Jobs, menu_icon_type='glyph', menu_icon_value='glyphicon-tasks'))
admin.add_view(ReportsView(Reports, menu_icon_type='glyph', menu_icon_value='glyphicon-list-alt'))
admin.add_view(LogsView(Logs, menu_icon_type='glyph', menu_icon_value='glyphicon-alert'))

#app.run(host = "127.0.0.1", ssl_context=(certsdir+'cert.pem', certsdir+'key.pem'))
#app.run(host = "127.0.0.1", port= "8001", debug=True)

