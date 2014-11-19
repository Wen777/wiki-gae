import json, os, re
from string import letters
import hmac
import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = '_hsiang'

"""
This segmaent described basic function for render template and wiki handeler.
"""

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# Make Secure Function.
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

#### I don't know what's following function's feature.
# def render_str(template, **params):
#     t = jinja_env.get_template(template)
#     return t.render(params)


class WikiHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and UserDB.by_id(int(uid))

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'

class MainPage(WikiHandler):
  def get(self):
    # self.render("front.html", user=user, posts=posts)
    self.render("front.html")

##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class UserDB(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return UserDB.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = UserDB.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return UserDB(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def wikiPageKey(name = 'default'):
    return db.Key.from_path('wikiPage', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    creator = db.StringProperty(required = True)
    modified_user = db.StringProperty(required = True)
    last_modified_user = db.StringProperty(required = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

    def as_dict(self):
        time_format = '%c'
        d = {'subject': self.subject,
             'content': self.content,
             'created': self.created.strftime(time_format),
             'last_modified': self.last_modified.strftime(time_format)}
        return d



# class BlogFront(BlogHandler):
#     def get(self):
#         posts = greetings = Post.all().order('-created')
#         if self.format == 'html':
#             self.render('front.html', posts = posts)
#         else:
#             return self.render_json([p.as_dict() for p in posts])

# class PostPage(BlogHandler):
#     def get(self, post_id):
#         key = db.Key.from_path('Post', int(post_id), parent=wikiPageKey())
#         post = db.get(key)

#         if not post:
#             self.error(404)
#             return
#         if self.format == 'html':
#             self.render("permalink.html", post = post)
#         else:
#             self.render_json(post.as_dict())

# class NewPost(BlogHandler):
#     def get(self):
#         if self.user:
#             self.render("newpost.html")
#         else:
#             self.redirect("/login")

#     def post(self):
#         if not self.user:
#             self.redirect('/blog')

#         subject = self.request.get('subject')
#         content = self.request.get('content')

#         if subject and content:
#             p = Post(parent = wikiPageKey(), subject = subject, content = content)
#             p.put()
#             self.redirect('/blog/%s' % str(p.key().id()))
#         else:
#             error = "subject and content, please!"
#             self.render("newpost.html", subject=subject, content=content, error=error)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

# class Signup(BlogHandler):
#     def get(self):
#         self.render("signup-form.html")

#     def post(self):
#         have_error = False
#         self.username = self.request.get('username')
#         self.password = self.request.get('password')
#         self.verify = self.request.get('verify')
#         self.email = self.request.get('email')

#         params = dict(username = self.username,
#                       email = self.email)

#         if not valid_username(self.username):
#             params['error_username'] = "That's not a valid username."
#             have_error = True

#         if not valid_password(self.password):
#             params['error_password'] = "That wasn't a valid password."
#             have_error = True
#         elif self.password != self.verify:
#             params['error_verify'] = "Your passwords didn't match."
#             have_error = True

#         if not valid_email(self.email):
#             params['error_email'] = "That's not a valid email."
#             have_error = True

#         if have_error:
#             self.render('signup-form.html', **params)
#         else:
#             self.done()

#     def done(self, *a, **kw):
#         raise NotImplementedError

# class Register(Signup):
#     def done(self):
#         #make sure the user doesn't already exist
#         u = UserDB.by_name(self.username)
#         if u:
#             msg = 'That user already exists.'
#             self.render('signup-form.html', error_username = msg)
#         else:
#             u = UserDB.register(self.username, self.password, self.email)
#             u.put()

#             self.login(u)
#             self.redirect('/blog/welcome')

# class Login(BlogHandler):
#     def get(self):
#         self.render('login-form.html')

#     def post(self):
#         username = self.request.get('username')
#         password = self.request.get('password')

#         u = UserDB.login(username, password)
#         if u:
#             self.login(u)
#             self.redirect('/blog/welcome')
#         else:
#             msg = 'Invalid login'
#             self.render('login-form.html', error = msg)

# class Logout(BlogHandler):
#     def get(self):
#         self.logout()
#         self.redirect('/signup')

# class Welcome(BlogHandler):
#     def get(self):
#         username = self.request.get('username')
#         if valid_username(username):
#             self.render('welcome.html', username = username)
#         else:
#             self.redirect('/blog/signup')

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([#('/signup', Signup),
                               #('/login', Login),
                               #('/logout', Logout),
                               ('/', MainPage),
                               #('/_edit' + PAGE_RE, EditPage),
                               #(PAGE_RE, WikiPage),
                               ],
                              debug=True)

# app = webapp2.WSGIApplication([('/', MainPage),
#                                ('/blog/?(?:.json)?', BlogFront),
#                                ('/blog/([0-9]+)(?:.json)?', PostPage),
#                                ('/blog/newpost', NewPost),
#                                ('/blog/signup', Register),
#                                ('/blog/login', Login),
#                                ('/blog/logout', Logout),
#                                ],
#                               debug=True)
