'''
    __G__ = "(G)bd249ce4"
    web
'''

from os import environ, getpid, path
from uuid import uuid4
from re import search, DOTALL
from re import compile as rcompile
from random import choice
from datetime import timedelta, datetime
from json import JSONEncoder, dumps
from string import ascii_uppercase
from platform import platform as pplatform
from shutil import disk_usage
from requests import get
from psutil import cpu_percent, virtual_memory, Process
from bson.objectid import ObjectId
from flask import Flask, flash, jsonify, redirect, request, session, url_for
from flask_mongoengine import MongoEngine
from wtforms.widgets import ListWidget, CheckboxInput
from wtforms import form, fields, validators, SelectMultipleField
from flask_admin import AdminIndexView, Admin, expose, BaseView
from flask_admin.menu import MenuLink
from flask_admin.babel import gettext
from flask_admin.contrib.mongoengine import ModelView
from flask_login import LoginManager, current_user, login_user, logout_user
from flask_bcrypt import Bcrypt
from flaskext.markdown import Markdown
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename
from pymongo import ASCENDING
from settings import defaultdb, json_settings, meta_files_settings, meta_reports_settings, meta_task_files_logs_settings, meta_users_settings
from redisqueue.qbqueue import QBQueue
from analyzer.logger.logger import ignore_excpetion
from analyzer.connections.redisconn import get_cache
from analyzer.connections.mongodbconn import CLIENT

SWITCHES = [('full', 'full'), ('behavior', 'behavior'), ('xref', 'xref'), ('tags', 'tags'), ('yara', 'yara'), ('language', 'language'), ('mitre', 'mitre'), ('topurl', 'topurl'), ('ocr', 'ocr'), ('enc', 'enc'), ('cards', 'cards'), ('creds', 'creds'), ('secrets', 'secrets'), ('patterns', 'patterns'), ('suspicious', 'suspicious'), ('dga', 'dga'), ('plugins', 'plugins'), ('visualize', 'visualize'), ('flags', 'flags'), ('icons', 'icons'), ('worldmap', 'worldmap'), ('spelling', 'spelling'), ('image', 'image'), ('phishing', 'phishing'), ('unicode', 'unicode'), ('bigfile', 'bigfile'), ('w_internal', 'w_internal'), ('w_original', 'w_original'), ('w_hash', 'w_hash'), ('w_words', 'w_words'), ('w_all', 'w_all'), ('ms_all', 'ms_all')]

def intro(filename, link):
    '''
    this function is needed for the home page intro
    '''
    intromarkdown = ""
    with ignore_excpetion(Exception):
        ret_request = get(link, verify=False, timeout=2)
        if ret_request.ok is True:
            intromarkdown = search(rcompile(r"\#\# Features.*", DOTALL), ret_request.text).group(0)
    if intromarkdown == "":
        with ignore_excpetion(Exception):
            readmefolder = path.abspath(path.join(path.dirname(__file__), filename))
            with open(readmefolder, "rU", encoding="utf-8") as file:
                intromarkdown = search(rcompile(r"\#\# Features.*", DOTALL), file.read()).group(0)
    return intromarkdown

def session_key(filename):
    '''
    get the generated session key
    '''
    key = ""
    with ignore_excpetion(Exception):
        readmefolder = path.abspath(path.join(path.dirname(__file__), filename))
        with open(readmefolder, "rU", encoding="utf-8") as file:
            key = file.read()
    return key

APP = Flask(__name__)
APP.secret_key = session_key("key.hex")
INTROMARKDOWN = intro("README.md", "https://raw.githubusercontent.com/qeeqbox/analyzer/master/README.md")
APP.config['MONGODB_SETTINGS'] = json_settings[environ["analyzer_env"]]["web_mongo"]
APP.config['SESSION_COOKIE_SAMESITE'] = "Lax"
QUEUE = QBQueue("analyzer", json_settings[environ["analyzer_env"]]["redis_settings"])
ANALYZER_TIMEOUT = json_settings[environ["analyzer_env"]]["analyzer_timeout"]
FUNCTION_TIMEOUT = json_settings[environ["analyzer_env"]]["function_timeout"]
MALWARE_FOLDER = json_settings[environ["analyzer_env"]]["malware_folder"]

MONGO_DB = MongoEngine()
MONGO_DB.init_app(APP)
BCRYPT = Bcrypt(APP)
LOGIN_MANAGER = LoginManager()
LOGIN_MANAGER.setup_app(APP)
CSRF = CSRFProtect()
CSRF.init_app(APP)
Markdown(APP)

class Namespace:
    '''
    this namespace for switches
    '''
    def __init__(self, kwargs):
        self.__dict__.update(kwargs)

def convert_size(_size):
    '''
    convert size to unit
    '''
    for _unit in ['B', 'KB', 'MB', 'GB']:
        if _size < 1024.0:
            return "{:.2f}{}".format(_size, _unit)
        _size /= 1024.0
    return "File is too big"

@LOGIN_MANAGER.user_loader
def load_user(user_id):
    '''
    load user
    '''
    return User.objects(id=user_id).first()

class User(MONGO_DB.Document):
    '''
    this class has all users
    '''
    login = MONGO_DB.StringField(max_length=80, unique=True)
    password = MONGO_DB.StringField(max_length=64)
    meta = meta_users_settings

    @property
    def is_authenticated(self):
        '''
        is the user authenticated or not
        '''
        return True

    @property
    def is_active(self):
        '''
        is the user active or not
        '''
        return True

    @property
    def is_anonymous(self):
        '''
        is the user anonymous (this function not used)
        '''
        return False

    def get_id(self):
        '''
        get user id from the database
        '''
        return str(self.id)

    def __unicode__(self):
        '''
        unicode
        '''
        return self.login

class UserView(ModelView):
    '''
    user view (visable)
    '''
    list_template = 'list.html'
    can_create = False
    can_delete = True
    can_edit = False

    def is_accessible(self):
        '''
        is accessible
        '''
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        '''
        if not accessible then go to login
        '''
        return redirect(url_for('admin.login_view', next=request.url))

    @expose('/')
    def index_view(self):
        '''
        User list route
        '''
        self._template_args['card_title'] = 'Current users'
        return super(UserView, self).index_view()

class Files(MONGO_DB.Document):
    '''
    files doc
    '''
    uuid = MONGO_DB.StringField()
    line = MONGO_DB.DictField()
    file = MONGO_DB.FileField()
    meta = meta_files_settings

class FilesView(ModelView):
    '''
    files view (visable)
    '''
    list_template = 'list.html'
    can_create = False
    can_delete = True
    can_edit = False
    column_searchable_list = ['uuid']

    def is_accessible(self):
        '''
        is accessible
        '''
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        '''
        if not accessible then go to login
        '''
        return redirect(url_for('admin.login_view', next=request.url))

    @expose('/')
    def index_view(self):
        '''
        files list route
        '''
        self._template_args['card_title'] = 'Uploaded files'
        return super(FilesView, self).index_view()

class Reports(MONGO_DB.Document):
    '''
    reports doc
    '''
    uuid = MONGO_DB.StringField()
    type = MONGO_DB.StringField()
    file = MONGO_DB.FileField()
    time = MONGO_DB.DateTimeField()
    meta = meta_reports_settings

class ReportsViewJSON(ModelView):
    '''
    json reports view (visable)
    '''
    list_template = 'list.html'
    can_create = False
    can_delete = True
    can_edit = False
    column_searchable_list = ['uuid']
    column_default_sort = ('time', True)

    def is_accessible(self):
        '''
        is accessible
        '''
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        '''
        if not accessible then go to login
        '''
        return redirect(url_for('admin.login_view', next=request.url))

    def get_query(self):
        '''
        return json object
        '''
        return Reports.objects(type="application/json")

    @expose('/')
    def index_view(self):
        '''
        json reports list route
        '''
        self._template_args['card_title'] = 'Generated JSON reports'
        return super(ReportsViewJSON, self).index_view()

class ReportsViewHTML(ModelView):
    '''
    html reports view (visable)
    '''
    list_template = 'list.html'
    can_create = False
    can_delete = True
    can_edit = False
    column_searchable_list = ['uuid']
    column_default_sort = ('time', True)

    def is_accessible(self):
        '''
        is accessible
        '''
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        '''
        if not accessible then go to login
        '''
        return redirect(url_for('admin.login_view', next=request.url))

    def get_query(self):
        '''
        return html object
        '''
        return Reports.objects(type="text/html")

    @expose('/')
    def index_view(self):
        '''
        html reports list route
        '''
        self._template_args['card_title'] = 'Generated HTML reports'
        return super(ReportsViewHTML, self).index_view()

class Logs(MONGO_DB.Document):
    '''
    logs doc
    '''
    uuid = MONGO_DB.StringField()
    type = MONGO_DB.StringField()
    file = MONGO_DB.FileField()
    time = MONGO_DB.DateTimeField()
    meta = meta_task_files_logs_settings

class LogsView(ModelView):
    '''
    logs view (visable)
    '''
    list_template = 'list.html'
    can_create = False
    can_delete = True
    can_edit = False
    column_searchable_list = ['uuid']
    column_default_sort = ('time', True)

    def is_accessible(self):
        '''
        is accessible
        '''
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        '''
        if not accessible then go to login
        '''
        return redirect(url_for('admin.login_view', next=request.url))

    @expose('/')
    def index_view(self):
        '''
        logs list route
        '''
        self._template_args['card_title'] = 'Generated logs'
        return super(LogsView, self).index_view()

class LoginForm(form.Form):
    '''
    login form (username and password)
    '''
    login = fields.StringField(render_kw={"placeholder":"Username", "autocomplete":"off"})
    password = fields.PasswordField(render_kw={"placeholder":"Password", "autocomplete":"off"})

    def validate_login(self, field):
        '''
        log in
        '''
        user = self.get_user()  #fix AttributeError: 'NoneType' object has no attribute 'password'
        if user is not None:
            if not BCRYPT.check_password_hash(user.password, self.password.data):
                raise validators.ValidationError('Invalid password')

    def get_user(self):
        '''
        get log in
        '''
        return User.objects(login=self.login.data).first()

class RegistrationForm(form.Form):
    '''
    register form (username and password)
    '''
    login = fields.StringField(render_kw={"placeholder":"Username"})
    password = fields.PasswordField(render_kw={"placeholder":"Password"})

    def validate_login(self, field):
        '''
        get log in
        '''
        if User.objects(login=self.login.data):
            raise validators.ValidationError('Duplicate username')

class CustomAdminIndexView(AdminIndexView):
    '''
    Custom login view
    '''
    @expose('/')
    def index(self):
        '''
        main route
        '''
        if not current_user.is_authenticated:
            return redirect(url_for('.login_view'))
        #return redirect("/stats")

        self._template_args['filename'] = "README.md @ https://github.com/qeeqbox/analyzer"
        self._template_args['intro'] = INTROMARKDOWN
        #self._template_args['location_tree'] = "Home"
        return super(CustomAdminIndexView, self).index()

    @expose('/login/', methods=['POST', 'GET'])
    def login_view(self):
        '''
        login route
        '''
        temp_form = LoginForm(request.form)
        if request.method == 'POST' and temp_form.validate():
            user = temp_form.get_user()
            if user is not None:
                login_user(user)

        if current_user.is_authenticated:
            session["navs"] = []
            return redirect(request.args.get('next') or url_for('.index'))

        self._template_args['form'] = temp_form
        self._template_args['active'] = "Login"
        self._template_args['intro'] = ""
        self._template_args['link'] = '<p>Register? <a href="{}">Click here</a></p>'.format(url_for('.register_view'))
        return super(CustomAdminIndexView, self).index()

    @expose('/register/', methods=('GET', 'POST'))
    def register_view(self):
        '''
        register route
        '''
        temp_form = RegistrationForm(request.form)
        if request.method == 'POST' and temp_form.validate():
            user = User()
            temp_form.populate_obj(user)
            if len(user["password"]) > 0 and len(user["login"]) > 0:
                user["password"] = BCRYPT.generate_password_hash(user["password"]).decode('utf-8')
                user.save()
                login_user(user)
                session["navs"] = []
                return redirect(url_for('.index'))

        self._template_args['form'] = temp_form
        self._template_args['active'] = "Register"
        self._template_args['intro'] = ""
        self._template_args['link'] = '*Please do not enter a used username or password<p><p>Login? <a href="{}">Click here</a></p>'.format(url_for('.login_view'))
        return super(CustomAdminIndexView, self).index()

    @expose('/logout/')
    def logout_view(self):
        '''
        logout route
        '''
        logout_user()
        session["navs"] = []
        return redirect(url_for('.index'))

    @expose('/toggled', methods=('GET', 'POST'))
    def is_toggled(self):
        '''
        toggled route (this will keep track of toggled items)
        '''
        with ignore_excpetion(Exception):
            if current_user.is_authenticated:
                json_content = request.get_json(silent=True)
                for key, value in json_content.items():
                    if value == "false":
                        session["navs"].remove(key)
                    else:
                        session["navs"].append(key)
        return jsonify("Done")

    def is_visible(self):
        '''
        Do not show items in the sidebar
        '''
        return False

class MultiCheckboxField(SelectMultipleField):
    '''
    this class will be used for mulit checckbox
    '''
    widget = ListWidget(prefix_label=False)
    option_widget = CheckboxInput()

class UploadForm(form.Form):
    '''
    needs more check
    '''
    choices = MultiCheckboxField('Assigned', choices=SWITCHES)
    file = fields.FileField(render_kw={"multiple": True})
    analyzertimeout = fields.SelectField('analyzertimeout', choices=[(30, '30sec analyzing timeout'), (60, '1min analyzing timeout'), (120, '2min analyzing timeout')], default=(ANALYZER_TIMEOUT), coerce=int)
    functiontimeout = fields.SelectField('functiontimeout', choices=[(10, '10sec logic timeout'), (20, '20sec logic timeout'), (30, '30sec logic timeout'), (40, '40sec logic timeout'), (50, '50sec logic timeout'), (60, '1min logic timeout'), (100, '1:40min logic timeout')], default=(FUNCTION_TIMEOUT), coerce=int)
    submit = fields.SubmitField(render_kw={"class":"btn"})
    submitandwait = fields.SubmitField('Submit And Wait', render_kw={"class":"btn"})
    __order = ('file', 'choices', 'analyzertimeout', 'functiontimeout', 'submit', 'submitandwait')
    def __iter__(self):
        temp_fields = list(super(UploadForm, self).__iter__())
        get_field = lambda fid: next((f for f in temp_fields if f.id == fid))
        return (get_field(fid) for fid in self.__order)

class CustomViewUploadForm(BaseView):
    '''
    upload file main form
    '''
    extra_js = ['/static/checktask.js']

    @expose('/', methods=['POST', 'GET'])
    def index(self):
        '''
        main route
        '''
        temp_form = UploadForm(request.form)
        if request.method == 'POST':
            uploaded_files = request.files.getlist("file")
            for file in uploaded_files:
                filename = ""
                uuid = str(uuid4())
                if file:
                    result = {}
                    filename = secure_filename(file.filename)
                    savetotemp = path.join(MALWARE_FOLDER, filename)
                    for item in request.form.getlist("choices"):
                        result.update({item:True})
                    result["file"] = savetotemp
                    result["uuid"] = uuid
                    result["analyzer_timeout"] = temp_form.analyzertimeout.data
                    result["function_timeout"] = temp_form.functiontimeout.data
                    files = Files()
                    files.uuid = uuid
                    files.line = result
                    files.file.put(file, content_type=file.content_type, filename=filename)
                    files.save()
                    file.seek(0)
                    file.save(savetotemp)
                    QUEUE.put(uuid, result)
                    if len(uploaded_files) == 1 and request.form.get('submitandwait') == 'Submit And Wait':
                        flash(gettext(uuid), 'successandwaituuid')
                    else:
                        flash(gettext("Done uploading {} Task ({})".format(filename, uuid)), 'success')
                else:
                    flash(gettext("Something wrong while uploading {} Task ({})".format(filename, uuid)), 'error')
        return self.render("upload.html", header="Scan File\\Files", form=temp_form, switches_details=get_cache("switches"))

    def is_accessible(self):
        '''
        is accessible
        '''
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        '''
        if not accessible then go to login
        '''
        return redirect(url_for('admin.login_view', next=request.url))

class BufferForm(form.Form):
    '''
    needs more check
    '''
    choices = MultiCheckboxField('Assigned', choices=SWITCHES)
    buffer = fields.TextAreaField(render_kw={"class":"buffer"})
    analyzertimeout = fields.SelectField('analyzertimeout', choices=[(30, '30sec'), (60, '1min'), (120, '2min')], default=int(ANALYZER_TIMEOUT), coerce=int)
    functiontimeout = fields.SelectField('functiontimeout', choices=[(10, '10sec'), (20, '20sec'), (30, '30sec'), (40, '40sec'), (50, '50sec'), (60, '60sec'), (100, '1:40min')], default=int(FUNCTION_TIMEOUT), coerce=int)
    submit = fields.SubmitField(render_kw={"class":"btn"})
    submitandwait = fields.SubmitField('Submit And Wait', render_kw={"class":"btn"})
    __order = ('buffer', 'choices', 'analyzertimeout', 'functiontimeout', 'submit', 'submitandwait')
    def __iter__(self):
        temp_fields = list(super(BufferForm, self).__iter__())
        get_field = lambda fid: next((f for f in temp_fields if f.id == fid))
        return (get_field(fid) for fid in self.__order)

class CustomViewBufferForm(BaseView):
    '''
    upload buffer main form
    '''
    extra_js = ['/static/checktask.js']

    @expose('/', methods=['POST', 'GET'])
    def index(self):
        '''
        main route
        '''
        temp_form = BufferForm(request.form)
        if request.method == 'POST':
            if temp_form.buffer.data != "":
                uuid = str(uuid4())
                result = {}
                for item in request.form.getlist("choices"):
                    result.update({item:True})
                filename = ''.join(choice(ascii_uppercase) for _ in range(8))
                savetotemp = path.join(MALWARE_FOLDER, filename)
                with open(savetotemp, "w") as tempfile:
                    tempfile.write(temp_form.buffer.data)
                with open(savetotemp, "rb") as tempfile:
                    result["file"] = savetotemp
                    result["uuid"] = uuid
                    result["analyzer_timeout"] = temp_form.analyzertimeout.data
                    result["function_timeout"] = temp_form.functiontimeout.data
                    files = Files()
                    files.uuid = uuid
                    files.line = result
                    files.file.put(tempfile, content_type="application/octet-stream", filename=filename)
                    files.save()
                    QUEUE.put(uuid, result)
                    if request.form.get('submitandwait') == 'Submit And Wait':
                        flash(gettext(uuid), 'successandwaituuid')
                    else:
                        flash(gettext('Done submitting buffer Task {}'.format(uuid)), 'success')
            else:
                flash(gettext("Something wrong"), 'error')
        return self.render("upload.html", header="Scan Buffer", form=temp_form, switches_details=get_cache("switches"))

    def is_accessible(self):
        '''
        is accessible
        '''
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        '''
        if not accessible then go to login
        '''
        return redirect(url_for('admin.login_view', next=request.url))

def get_stats():
    '''
    get stats from databases
    '''
    stats = {}
    with ignore_excpetion(Exception):
        for coll in (defaultdb["reportscoll"], defaultdb["filescoll"], "fs.chunks", "fs.files"):
            if coll in CLIENT[defaultdb["dbname"]].list_collection_names():
                stats.update({"[{}] Collection".format(coll):"Exists"})
            else:
                stats.update({"[{}] Collection".format(coll):"Does not exists"})
    with ignore_excpetion(Exception):
        stats.update({"[Reports] Total reports":CLIENT[defaultdb["dbname"]][defaultdb["reportscoll"]].find({}).count(),
                      "[Reports] Total used space":"{}".format(convert_size(CLIENT[defaultdb["dbname"]].command("collstats", defaultdb["reportscoll"])["storageSize"] + CLIENT[defaultdb["dbname"]].command("collstats", defaultdb["reportscoll"])["totalIndexSize"]))})
    with ignore_excpetion(Exception):
        stats.update({"[Files] Total files uploaded":CLIENT[defaultdb["dbname"]][defaultdb["filescoll"]].find({}).count()})
    with ignore_excpetion(Exception):
        stats.update({"[Files] Total uploaded files size":"{}".format(convert_size(CLIENT[defaultdb["dbname"]]["fs.chunks"].find().count() * 255 * 1000))})
    with ignore_excpetion(Exception):
        stats.update({"[Users] Total users":CLIENT[defaultdb["dbname"]][defaultdb["userscoll"]].find({}).count()})
    with ignore_excpetion(Exception):
        total, used, free = disk_usage("/")
        stats.update({"CPU memory":cpu_percent(),
                      "Memory used":virtual_memory()[2],
                      "Current process used memory":"{}".format(convert_size(Process(getpid()).memory_info().rss)),
                      "Total disk size":"{}".format(convert_size(total)),
                      "Used disk size":"{}".format(convert_size(used)),
                      "Free disk size":"{}".format(convert_size(free)),
                      "Host platform":pplatform()})
    CLIENT.close()
    return stats

class CustomStatsView(BaseView):
    '''
    Stats view
    '''
    @expose('/', methods=['GET'])
    def index(self):
        '''
        state route
        '''
        return self.render("stats.html", stats=get_stats())

    def is_accessible(self):
        '''
        is accessible
        '''
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        '''
        if not accessible then go to login
        '''
        return redirect(url_for('admin.login_view', next=request.url))

def find_and_srot(database, collection, key, var):
    '''
    hmm finding by time is weird?
    '''
    temp_list = []
    if key == "time":
        items = list(CLIENT[database][collection].find().sort([('_id', -1)]).limit(1))
    else:
        items = list(CLIENT[database][collection].find({key: {"$gt": var}}).sort([(key, ASCENDING)]))
    for item in items:
        temp_list.append("{} {}".format(item["time"].isoformat(), item["message"]))
    if len(temp_list) > 0:
        return "\n".join(temp_list), str(items[-1]["_id"])
    return "", 0

def get_last_logs(json):
    '''
    get last item from logs
    '''
    items = []
    if json['id'] == 0:
        items, startid = find_and_srot(defaultdb["dbname"], defaultdb["alllogscoll"], "time", datetime.now())
    else:
        items, startid = find_and_srot(defaultdb["dbname"], defaultdb["alllogscoll"], "_id", ObjectId(json['id']))
    return {"id":startid, "logs":items}

class CustomLogsView(BaseView):
    '''
    logs view
    '''
    extra_js = ['/static/activelogs.js']

    @expose('/', methods=['GET', 'POST'])
    def index(self):
        '''
        main entry
        '''
        if request.method == 'GET':
            return self.render("activelogs.html")
        elif request.method == 'POST':
            if request.json:
                json_content = request.get_json(silent=True)
                return dumps(get_last_logs(json_content))
        return jsonify({"Error":"Something wrong"})


    def is_accessible(self):
        '''
        is accessible
        '''
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        '''
        if not accessible then go to login
        '''
        return redirect(url_for('admin.login_view', next=request.url))

class CheckTask(BaseView):
    '''
    check task view (This acts as api)
    '''
    @expose('/', methods=['POST', 'GET'])
    def index(self):
        '''
        check task route
        '''
        if request.method == 'POST':
            if request.json:
                json_content = request.get_json(silent=True)
                item = CLIENT[defaultdb["dbname"]][defaultdb["reportscoll"]].find_one({"uuid":json_content["uuid"], "type":"text/html"})
                if item:
                    return jsonify({"Task":str(item["file"])})
            return jsonify({"Task":""})
        return self.render("activelogs.html")

    def is_visible(self):
        '''
        not visable in the bar (just an api)
        '''
        return False

    def is_accessible(self):
        '''
        is accessible
        '''
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        '''
        if not accessible then go to login
        '''
        return redirect(url_for('admin.login_view', next=request.url))

class TimeEncoder(JSONEncoder):
    '''
    json encoder for time
    '''
    def default(self, obj):
        '''
        override default
        '''
        if isinstance(obj, datetime):
            return obj.astimezone().strftime("%Y-%m-%d %H:%M:%S.%f")
        return JSONEncoder.default(self, obj)

def find_items_without_coll(database, collection, items):
    '''
    ???
    '''
    temp_dict = {}
    for item in items:
        if item != '':
            temp_ret = CLIENT[database][collection].find_one({"_id":ObjectId(item)}, {'_id': False})
            if temp_ret is not None:
                temp_dict.update({item:temp_ret})
    return temp_dict

class CustomMenuLink(MenuLink):
    '''
    items will the header top left
    '''
    def is_accessible(self):
        '''
        is accessible
        '''
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        '''
        if not accessible then go to login
        '''
        return redirect(url_for('admin.login_view', next=request.url))

class StarProject(MenuLink):
    '''
    ??
    '''
    def is_accessible(self):
        '''
        is accessible
        '''
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        '''
        if not accessible then go to login
        '''
        return redirect(url_for('admin.login_view', next=request.url))

ADMIN = Admin(APP, "QeeqBox", index_view=CustomAdminIndexView(url='/'), base_template='base.html', template_mode='bootstrap3')
ADMIN.add_link(CustomMenuLink(name='', category='', url="https://github.com/qeeqbox/analyzer", icon_type='glyph', icon_value='glyphicon-star'))
ADMIN.add_link(CustomMenuLink(name='', category='', url="https://github.com/qeeqbox/analyzer/archive/master.zip", icon_type='glyph', icon_value='glyphicon-download-alt'))
ADMIN.add_link(CustomMenuLink(name='', category='', url="https://github.com/qeeqbox/analyzer/subscription", icon_type='glyph', icon_value='glyphicon glyphicon-eye-open'))
ADMIN.add_link(CustomMenuLink(name='Logout', category='', url="/logout", icon_type='glyph', icon_value='glyphicon glyphicon-user'))
ADMIN.add_view(CustomViewBufferForm(name="Buffer", endpoint='buffer', menu_icon_type='glyph', menu_icon_value='glyphicon-edit', category='Analyze'))
ADMIN.add_view(CustomViewUploadForm(name="Upload", endpoint='upload', menu_icon_type='glyph', menu_icon_value='glyphicon-upload', category='Analyze'))
ADMIN.add_view(ReportsViewHTML(Reports, name="HTML", endpoint='reportshtml', menu_icon_type='glyph', menu_icon_value='glyphicon-list-alt', category='Reports'))
ADMIN.add_view(ReportsViewJSON(Reports, name="JSON", endpoint='reportsjson', menu_icon_type='glyph', menu_icon_value='glyphicon-list-alt', category='Reports'))
ADMIN.add_view(LogsView(Logs, name='Tasks', menu_icon_type='glyph', menu_icon_value='glyphicon-info-sign', category='Logs'))
ADMIN.add_view(CustomLogsView(name="Active", endpoint='activelogs', menu_icon_type='glyph', menu_icon_value='glyphicon-flash', category='Logs'))
ADMIN.add_view(CustomStatsView(name="Stats", endpoint='stats', menu_icon_type='glyph', menu_icon_value='glyphicon-stats'))
ADMIN.add_view(FilesView(Files, menu_icon_type='glyph', menu_icon_value='glyphicon-file'))
ADMIN.add_view(UserView(User, menu_icon_type='glyph', menu_icon_value='glyphicon-user'))
ADMIN.add_view(CheckTask('Task', endpoint='task', menu_icon_type='glyph', menu_icon_value='glyphicon-user'))
#app.run(host = "127.0.0.1", ssl_context=(certsdir+'cert.pem', certsdir+'key.pem'))
#app.run(host = "127.0.0.1", port= "8001", debug=True)

@APP.before_request
def before_request():
    '''
    needed session fields
    '''
    session.permanent = True
    APP.permanent_session_lifetime = timedelta(minutes=60)
    session.modified = True
