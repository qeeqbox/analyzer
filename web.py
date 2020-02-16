__G__ = "(G)bd249ce4"

from flask import Flask, flash, jsonify, redirect, request, url_for, render_template
from flask_mongoengine import MongoEngine
from wtforms import form, fields, validators, SelectMultipleField
from flask_admin import AdminIndexView, Admin, expose, BaseView
from flask_admin.menu import MenuLink
from flask_admin.babel import gettext
from flask_admin.contrib.mongoengine import ModelView
from flask_login import LoginManager,current_user,login_user,logout_user
from flask_bcrypt import Bcrypt
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename
from uuid import uuid4
from tempfile import gettempdir
from os import environ, getpid, path, path
from datetime import datetime
from flask_wtf.csrf import CSRFProtect
from requests import get
from flaskext.markdown import Markdown
from pymongo import ASCENDING, MongoClient
from platform import platform as pplatform
from psutil import cpu_percent, virtual_memory, Process
from shutil import disk_usage
from settings import json_settings, mongodb_settings_docker, mongodb_settings_local, defaultdb,jobsqueuedb,meta_users_settings,meta_jobs_settings,meta_files_settings, meta_reports_settings, meta_task_files_logs_settings, __V__
from wtforms.widgets import ListWidget, CheckboxInput
from bson.objectid import ObjectId
from json import JSONEncoder, dumps
from re import compile, search, DOTALL
#import logging
#logging.basicConfig(level=logging.DEBUG)

switches = [('full','full'),('behavior','behavior'),('xref','xref'),('yara','yara'),('language','language'),('mitre','mitre'),('topurl','topurl'),('ocr','ocr'),('enc','enc'),('cards','cards'),('creds','creds'),('patterns','patterns'),('suspicious','suspicious'),('dga','dga'),('plugins','plugins'),('visualize','visualize'),('flags','flags'),('icons','icons'),('worldmap','worldmap'),('spelling','spelling'),('image','image'),('phishing','phishing'),('unicode','unicode'),('bigfile','bigfile'),('w_internal','w_internal'),('w_original','w_original'),('w_hash','w_hash'),('w_words','w_words'),('w_all','w_all'),('ms_all','ms_all')]
switches_details = '''
Analysis switches:
--behavior            check with generic detections
--xref                get cross references
--yara                analyze with yara module (Disable this for big files)
--language            analyze words against english language
--mitre               map strings to mitre
--topurl              get urls and check them against top 10000
--ocr                 get all ocr text
--enc                 find encryptions
--cards               find credit cards
--creds               find credit cards
--patterns            find common patterns
--suspicious          find suspicious strings
--dga                 find Domain generation algorithms
--plugins             scan with external plugins
--visualize           visualize some artifacts
--flags               add countries flags to html
--icons               add executable icons to html
--worldmap            add world map to html
--spelling            force spelling check
--image               add similarity image to html
--full                analyze using all modules
--phishing            analyze phishing content
Force analysis switches:
--unicode             force extracting ascii
--bigfile             force analyze big files
Whitelist switches:
--w_internal          find it in white list by internal name
--w_original          find it in white list by original name
--w_hash              find it in white list by hash
--w_words             check extracted words against whitelist
--w_all               find it in white list
Online multiscanner options:
--ms_all              check hash in different multiscanner platforms(requires API keys)'''

def intro(filename, link):
    intromarkdown = ""
    try:
        r = get(link,verify=False, timeout=2)
        if r.text!= "" and r.ok:
            intromarkdown = search(compile(r"\#\# General Features.*",DOTALL),r.text).group(0)
    except:
        pass

    if intromarkdown == "":
        try:
            readmefolder = path.abspath(path.join(path.dirname( __file__ ),filename))
            with open(readmefolder,"rU", encoding="utf-8") as f:
                intromarkdown = search(compile(r"\#\# General Features.*",DOTALL),f.read()).group(0)
        except:
            pass
    return intromarkdown

def session_key(filename):
    key = ""
    try:
        readmefolder = path.abspath(path.join(path.dirname( __file__ ),filename))
        with open(readmefolder,"rU", encoding="utf-8") as f:
            key = f.read()
    finally:
        return key

app = Flask(__name__)
app.secret_key = session_key("key.hex")
intromarkdown = intro("README.md","https://raw.githubusercontent.com/qeeqbox/analyzer/master/README.md")
conn = None


if environ["analyzer_env"] == "docker":
    conn = MongoClient(json_settings["mongo_settings_docker"])
    app.config['MONGODB_SETTINGS'] = mongodb_settings_docker
elif environ["analyzer_env"] == "local":
    conn = MongoClient(json_settings["mongo_settings_local"])
    app.config['MONGODB_SETTINGS'] = mongodb_settings_local
else:
    exit()

db = MongoEngine()
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.setup_app(app)
csrf = CSRFProtect()
csrf.init_app(app)
Markdown(app)

class Namespace:
    def __init__(self, kwargs):
        self.__dict__.update(kwargs)

def convert_size(s):
    for u in ['B','KB','MB','GB']:
        if s < 1024.0:
            return "{:.2f}{}".format(s,u)
        else:
            s /= 1024.0
    return "File is too big"

@login_manager.user_loader
def load_user(user_id):
    return User.objects(id=user_id).first()

class User(db.Document):
    login = db.StringField(max_length=80, unique=True)
    password = db.StringField(max_length=64)
    meta = meta_users_settings

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
    list_template = 'list.html'
    can_create = False
    can_delete = True
    can_edit = False

    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        if not self.is_accessible():
            return redirect(url_for('admin.login_view', next=request.url))

    @expose('/')
    def index_view(self):
         self._template_args['card_title'] = 'Current users'
         return super(UserView, self).index_view()

class Jobs(db.Document):
    jobID = db.StringField()
    status = db.StringField()
    created = db.DateTimeField()
    started = db.DateTimeField()
    finished = db.DateTimeField()
    data = db.DictField()
    meta = meta_jobs_settings

class QueueView(ModelView):
    list_template = 'listactivelogs.html'
    can_create = False
    can_delete = False
    can_edit = True
    column_searchable_list = ['jobID']
    extra_js = ['/static/jobs_style.js ']

    def is_accessible(self):
        return current_user.is_authenticated

    @expose('/')
    def index_view(self):
         self._template_args['card_title'] = 'All jobs in queue'
         return super(QueueView, self).index_view()


class Files(db.Document):
    uuid = db.StringField()
    line = db.DictField()
    file = db.FileField()
    meta = meta_files_settings

class FilesView(ModelView):
    list_template = 'list.html'
    can_create = False
    can_delete = True
    can_edit = False
    column_searchable_list = ['uuid']

    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        if not self.is_accessible():
            return redirect(url_for('admin.login_view', next=request.url))

    @expose('/')
    def index_view(self):
         self._template_args['card_title'] = 'Uploaded files'
         return super(FilesView, self).index_view()

class Reports(db.Document):
    uuid = db.StringField()
    type = db.StringField()
    file = db.FileField()
    time = db.DateTimeField()
    meta = meta_reports_settings

class ReportsViewJSON(ModelView):
    list_template = 'list.html'
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

    def get_query(self):            
        return Reports.objects(type="application/json")

    @expose('/')
    def index_view(self):
         self._template_args['card_title'] = 'Generated JSON reports'
         return super(ReportsViewJSON, self).index_view()

class ReportsViewHTML(ModelView):
    list_template = 'list.html'
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

    def get_query(self):            
        return Reports.objects(type="text/html")

    @expose('/')
    def index_view(self):
         self._template_args['card_title'] = 'Generated HTML reports'
         return super(ReportsViewHTML, self).index_view()

class Logs(db.Document):
    uuid = db.StringField()
    type = db.StringField()
    file = db.FileField()
    time = db.DateTimeField()
    meta = meta_task_files_logs_settings

class LogsView(ModelView):
    list_template = 'list.html'
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

    @expose('/')
    def index_view(self):
         self._template_args['card_title'] = 'Generated logs'
         return super(LogsView, self).index_view()

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
        #return redirect("/stats")

        self._template_args['filename'] = "README.md @ https://github.com/qeeqbox/analyzer"
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
    analyzertimeout = fields.SelectField('analyzertimeout',choices=[(30, '30sec analyzing timeout'), (60, '1min analyzing timeout'), (120, '2min analyzing timeout')],default=(json_settings["analyzer_timeout"]),coerce=int)
    functiontimeout = fields.SelectField('functiontimeout',choices=[(10, '10sec logic timeout'), (20, '20sec logic timeout'), (30, '30sec logic timeout'), (40, '40sec logic timeout'), (50, '50sec logic timeout'), (60, '60sec logic timeout'),(100,'1:40min logic timeout')],default=(json_settings["function_timeout"]),coerce=int)
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
        return self.render("upload.html",form=form, switches_details=switches_details)

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
        return self.render("upload.html",form=form, switches_details=switches_details)

    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        if not self.is_accessible():
            return redirect(url_for('admin.login_view', next=request.url))

def get_stats():
    #lazy check stats
    stats = {}
    try:
        if jobsqueuedb["jobscoll"] in conn[jobsqueuedb["dbname"]].list_collection_names():
            stats.update({"[{}] Collection".format(jobsqueuedb["jobscoll"]):"Exists"})
        else:
            stats.update({"[{}] Collection".format(jobsqueuedb["jobscoll"]):"Does not exists"})
    except:
        pass
    try:
        for coll in (defaultdb["reportscoll"],defaultdb["filescoll"],"fs.chunks","fs.files"):
            if coll in conn[defaultdb["dbname"]].list_collection_names():
                stats.update({"[{}] Collection".format(coll):"Exists"})
            else:
                stats.update({"[{}] Collection".format(coll):"Does not exists"})
    except:
        pass
    try:
        stats.update({  "[Queue] status":True if conn[jobsqueuedb["dbname"]][jobsqueuedb["jobscoll"]].find_one({'status': 'ON__'},{'_id': False}) else False,
                        "[Queue] Total jobs ": conn[jobsqueuedb["dbname"]][jobsqueuedb["jobscoll"]].find({"status" : {"$nin" : ["ON__","OFF_"]}}).count(),
                        "[Queue] Total finished jobs":conn[jobsqueuedb["dbname"]][jobsqueuedb["jobscoll"]].find({'status': 'done'}).count(),
                        "[Queue] Total waiting jobs":conn[jobsqueuedb["dbname"]][jobsqueuedb["jobscoll"]].find({'status': 'wait'}).count()})
                        
    #get total disk usage
    #"[Queue] Used space":"{} of {}".format(convert_size(conn[db].command("dbstats")["fsUsedSize"]),convert_size(conn[db].command("dbstats")["fsTotalSize"]))

    except:
        pass
    try:
        stats.update({"[Reports] Total reports":conn[defaultdb["dbname"]][defaultdb["reportscoll"]].find({}).count(),
                      "[Reports] Total used space":"{}".format(convert_size(conn[defaultdb["dbname"]].command("collstats",defaultdb["reportscoll"])["storageSize"] + conn[defaultdb["dbname"]].command("collstats",defaultdb["reportscoll"])["totalIndexSize"]))})
    except:
        pass
    try:
        stats.update({"[Files] Total files uploaded":conn[defaultdb["dbname"]][defaultdb["filescoll"]].find({}).count()})
    except:
        pass
    try:
        stats.update({"[Files] Total uploaded files size":"{}".format(convert_size(conn[defaultdb["dbname"]]["fs.chunks"].find().count() * 255 * 1000))})
    except:
        pass
    try:
        stats.update({"[Users] Total users":conn[defaultdb["dbname"]][defaultdb["userscoll"]].find({}).count()})
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

#hmm finding by time is weird?
def find_and_srot(db,col,key,var):
    _list = []
    
    if key == "time":
        items = list(conn[db][col].find().sort([('_id', -1)]).limit(1))
    else:
        items = list(conn[db][col].find({key: {"$gt": var}}).sort([(key,ASCENDING)]))
    
    for item in items:
        _list.append("{} {}".format(item["time"].isoformat(),item["message"]))
    if len(_list) > 0:
        return "\n".join(_list),str(items[-1]["_id"])
    else:
        return "",0

def get_last_logs(json):
    items = []
    if json['id'] == 0:
        items,startid = find_and_srot(defaultdb["dbname"],defaultdb["alllogscoll"],"time",datetime.now())
    else:
        items,startid = find_and_srot(defaultdb["dbname"],defaultdb["alllogscoll"],"_id",ObjectId(json['id']))
    return {"id":startid,"logs":items}

class CustomLogsView(BaseView):
    extra_js = ['/static/activelogs.js']

    @expose('/', methods=['GET','POST'])
    def index(self):
        if request.method == 'GET':
            return self.render("activelogs.html")
        elif request.method == 'POST':
            if request.json:
                json_content = request.get_json(silent=True)
                return dumps(get_last_logs(json_content))
        else:
            return jsonify({"Error":"Something wrong"})


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

def find_items_without_coll(db,col,items):
    _dict = {}
    for item in items:
        if item != '':
            ret = conn[db][col].find_one({"_id":ObjectId(item)},{'_id': False})
            if ret != None:
                _dict.update({item:ret})
    return _dict

class CustomDBupdate(BaseView):
    @expose('/', methods=['POST'])
    def index(self):
        if request.json:
            json_content = request.get_json(silent=True)
            items = find_items_without_coll(jobsqueuedb["dbname"],jobsqueuedb["jobscoll"],json_content)
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

admin = Admin(app, "QeeqBox Analyzer {}".format(__V__[7:]) , index_view=CustomAdminIndexView(url='/'),base_template='base.html' , template_mode='bootstrap3')
admin.add_link(CustomMenuLink(name='', category='', url="https://github.com/qeeqbox/analyzer", icon_type='glyph', icon_value='glyphicon-star'))
admin.add_link(CustomMenuLink(name='', category='', url="https://github.com/qeeqbox/analyzer/archive/master.zip", icon_type='glyph', icon_value='glyphicon-download-alt'))
admin.add_link(CustomMenuLink(name='', category='', url="https://github.com/qeeqbox/analyzer/subscription", icon_type='glyph', icon_value='glyphicon glyphicon-eye-open'))
admin.add_link(CustomMenuLink(name='Logout', category='', url="/logout", icon_type='glyph', icon_value='glyphicon glyphicon-user'))
admin.add_view(CustomDBupdate(name="DBinfo",endpoint='dbinfo',menu_icon_type='glyph', menu_icon_value='glyphicon-stats'))
admin.add_view(CustomViewBufferForm(name="Buffer",endpoint='buffer',menu_icon_type='glyph', menu_icon_value='glyphicon-edit',category='Analyze'))
admin.add_view(CustomViewUploadForm(name="Upload",endpoint='upload',menu_icon_type='glyph', menu_icon_value='glyphicon-upload',category='Analyze'))
admin.add_view(ReportsViewHTML(Reports,name="HTML",endpoint='reportshtml', menu_icon_type='glyph', menu_icon_value='glyphicon-list-alt',category='Reports'))
admin.add_view(ReportsViewJSON(Reports,name="JSON",endpoint='reportsjson',menu_icon_type='glyph', menu_icon_value='glyphicon-list-alt',category='Reports'))
admin.add_view(LogsView(Logs,name='Tasks',menu_icon_type='glyph', menu_icon_value='glyphicon-info-sign',category='Logs'))
admin.add_view(CustomLogsView(name="Active",endpoint='activelogs',menu_icon_type='glyph', menu_icon_value='glyphicon-flash',category='Logs'))
admin.add_view(CustomStatsView(name="Stats",endpoint='stats',menu_icon_type='glyph', menu_icon_value='glyphicon-stats'))
admin.add_view(FilesView(Files,menu_icon_type='glyph', menu_icon_value='glyphicon-file'))
admin.add_view(QueueView(Jobs, menu_icon_type='glyph', menu_icon_value='glyphicon-tasks'))
admin.add_view(UserView(User, menu_icon_type='glyph', menu_icon_value='glyphicon-user'))

#app.run(host = "127.0.0.1", ssl_context=(certsdir+'cert.pem', certsdir+'key.pem'))
#app.run(host = "127.0.0.1", port= "8001", debug=True)

