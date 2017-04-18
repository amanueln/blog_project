import os
import jinja2
import webapp2
import codecs 
import re
import hashlib
import hmac
import random
import string
from google.appengine.ext import db


SECRET ='6YDYJZvM_mowfM9N8_HDZpRDoS_TfdcfNoh'

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)

    

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
    
    def hash_str(self,s):
        #hashing in hmac
        return hmac.new(SECRET, s).hexdigest()
    
    def make_secure_val(self,s):
        #takes the cookie and secures it.
        return "%s|%s" % (s, self.hash_str(s))
    
    def check_secure_val(self,h):
        # checks to see if cookie is secure.
        val = h.split('|')[0]
        if h == self.make_secure_val(val):
            return val
    def set_secure_cookie(self, name, val):
        cookie_val = self.make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))
    
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))
    
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and self.check_secure_val(cookie_val)
    
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def make_salt():
        return ''.join(random.choice(string.letters) for x in xrange(5))

# Implement the function valid_pw() that returns True if a user's password 
# matches its hash. You will need to modify make_pw_hash.

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


#stores blog posts
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)


class Blog(db.Model):
        subject = db.StringProperty(required = True)
        content = db.TextProperty(required = True)
        created = db.DateTimeProperty(auto_now_add = True)
        last_modified = db.DateTimeProperty(auto_now = True)
        user = db.IntegerProperty ()


#stores registration data
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()
    
    
    
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    
    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw, email)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
    
class Comment(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name

    
class Rot13Handler(Handler):
    def post(self):
        plain_text = self.request.get("text")
        rot13_text = codecs.encode(plain_text, 'rot_13')
        self.render("rot_13.html", text=rot13_text)

    def get(self):
        text = ""
        self.render('rot_13.html', text=text)

USER_RE =re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
USER_PW = re.compile(r"^.{3,20}$")
USER_EMAIL =re.compile(r"^[\S]+@[\S]+.[\S]+$")

    
def valid_username(username):
        return USER_RE.match(username)
def valid_password(password):
        return USER_PW.match(password)
def valid_verify(verify):
        return USER_PW.match(verify)
def valid_email(email):
        return USER_EMAIL.match(username)       

class SignUpHandler(Handler):
    def post(self):
        
        have_error = False
        username = self.request.get("user")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        
        params = dict(username = username,email=email)
        
        if not valid_username(username):
            params['error_username'] = "That's not a valid username. Enter again"
            have_error = True
        if not valid_password(password):
            params['error_password']="not a valid password. Enter again"
            have_error= True
        if not password == verify:
            params['error_verify']="does not match"
            have_error= True
        
        
        if have_error:
            self.render('user_signup.html', **params)
        else:
                #make sure the user doesn't already exist
            u = User.by_name(username)
            if u:
                msg = 'That user already exists.'
                self.render('user_signup.html', error_username = msg)
            else:
                u = User.register(username,password,email)
                u.put()

                self.login(u)
                #print('congrats')
                #self.write("congrats main")
                username = u.name
                self.render('congrats.html', username= u.name)
    
    def get(self):
        self.render("user_signup.html")

class Login(SignUpHandler):
    def get(self):
        self.render("login.html")
    def post(self):
        username = self.request.get("user")
        password = self.request.get("password")
        
        u = User.login(username, password)
        if u:
            self.login(u)
            #self.redirect('/')
            self.redirect("/myblog")
        else:
            msg = 'Invalid login'
            self.render('login.html', error_username = msg)

class Logout(Handler):
    def get(self):
        logout = self.logout()
        self.render('/', logout= logo)

#start of blog posting page
class PostPage(Handler):
       def get(self, post_id):
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

class NewPost(Handler):
    def default_newpost(self, subject="", content=""):
        self.render('newblog.html', subject=subject, content=content)
    def get(self):
        if not self.user:
            self.redirect("/login")
        else:
            self.login(self.user)
            self.default_newpost()
            #self.write("post")
    def post(self):
            get_title = self.request.get("subject")
            get_blog = self.request.get("content")
            get_user = self.user.key().id()

            if get_title and get_blog:
                p = Blog(parent = blog_key(), subject = get_title, content = get_blog, user = get_user)
                p.put()
                self.redirect('/%s' % str(p.key().id()))
                #b = Blog(subject=get_title, content=get_blog)
                #b.put()
                #alert="blog posted"
                #self.render("newblog.html",alert=alert)
            else:
                alert = "you need to submit both subject and blog content"
                self.render("newblog.html",subject=get_title, content= get_blog, alert=alert)


class MainPage(Handler):
    def users_key(group = 'default'):
        return db.Key.from_path('users', group)
    def default_blog(self, subject="", content=""):
        blog_db = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC limit 10")
        self.render("main.html",subject=subject, content=content, blog_db= blog_db)
    def get(self):
        self.default_blog()

    def post(self):
        if not self.user:
            self.render("login.html")
        else:
            self.default_blog()
            
class MyBlogs(Handler):
    def default_blog(self, subject="", content=""):
        user_id = self.user.key().id()
        my_blogs = Blog.all().filter('user =',  user_id)
        user = self.user.name
        self.render("myblog.html",subject=subject, content=content, blog_db= my_blogs, username= user)
        
       
    def get(self):
        if not self.user:
            self.redirect("/login")
        else:
             self.default_blog()
            
             
    def post(self):
        pass

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/myblog', MyBlogs),
                               ('/rot13', Rot13Handler),
                               ('/signup', SignUpHandler),
                               ('/login', Login),
                               ('/newpost', NewPost),
                               ('/([0-9]+)', PostPage),
                              ], debug=True)
