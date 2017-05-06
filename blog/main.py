import os
import jinja2
import webapp2
import re
import hashlib
import hmac
import random
import string
from google.appengine.ext import db


SECRET ='6YDYJZvM_mowfM9N8_HDZpRDoS_TfdcfNoh'

template_dir = os.path.join(  os.path.dirname(__file__), 'templates')
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
# matches its hash. 

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


#blog key
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

#stores blog data of users
class Blog(db.Model):
        subject = db.StringProperty(required = True)
        content = db.TextProperty(required = True)
        created = db.DateTimeProperty(auto_now_add = True)
        last_modified = db.DateTimeProperty(auto_now = True)
        user = db.IntegerProperty(required = True)
        blogger_name = db.StringProperty()
        likes = db.IntegerProperty(required=True)
        users_liked = db.StringListProperty(required=True)


#stores registration data of users
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

#comment key
def comment_key(name = 'default'):
    return db.Key.from_path('comments', name)

#db for comments
class Comment(db.Model):
    content = db.TextProperty(required=True)
    post_id = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    commentor = db.StringProperty(required=True)


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

#handles rregistration
class SignUpHandler(Handler):
    def post(self):
        
        have_error = False
        username = self.request.get("user")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        
        params = dict(username = username,email=email,user=self.user)
        
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
                self.render('user_signup.html', error_username = msg, user=self.user)
            else:
                u = User.register(username,password,email)
                u.put()
                self.login(u)
                username = u.name
                self.render('congrats.html', username= u.name, user=self.user)
    
    def get(self):
        self.render("user_signup.html", user=self.user)

class Login(SignUpHandler):
    def get(self):
        user=self.user
        self.render("login.html", user=self.user)
    
    def post(self):
        username = self.request.get("user")
        password = self.request.get("password")
        
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect("/myblog")
        else:
            msg = 'Invalid login'
            return self.render('login.html', error_username = msg, user=self.user)

class Logout(Handler):
    def get(self):
        self.logout()
        return self.redirect('/')

#handles making new posts
class NewPost(Handler):
    def default_newpost(self, subject="", content=""):
        self.render('newblog.html', subject=subject, content=content, user=self.user)
    
    def get(self):
        if not self.user:
            return self.redirect("/login")
        
        self.login(self.user)
        self.default_newpost()
            
    
    def post(self):
            if not self.user:
                return self.redirect("/login")
            
            get_title = self.request.get("subject")
            get_blog = self.request.get("content")
            get_user = self.user.key().id()
            blogger_username = self.user.name
            likes = 0
            

            if get_title and get_blog:
                p = Blog(parent = blog_key(), subject = get_title, content = get_blog, user = get_user, blogger_name = blogger_username, likes=likes)
                p.put()
                return self.redirect('/blog/%s' % str(p.key().id()))
        
            else:
                alert = "you need to submit both subject and blog content"
                return self.render("newblog.html",subject=get_title, content= get_blog, alert=alert, user=self.user)

#posts all blogs and comments
class PostPage(Handler):
    def get(self, post_id):
        if not self.user:
            return self.redirect('/login')
        comment_db = Comment.all().filter( "post_id = ", str(post_id)).order("-created").fetch(15)
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            return self.write("no post")
        
        return self.render("permalink.html", post = post, comment=comment_db, user=self.user)
    
    def post(self,post_id):
        if self.user:
            comment =self.request.get('comment')
            if not comment:
                return self.write("no comment enterterd")
            
            comment = Comment(parent=comment_key(), content=comment,
                        commentor=self.user.name, post_id=post_id)
            comment.put()
            return self.redirect('/blog/%s' % str(post_id))
        
        

class DeletePost(Handler):
    def get(self,post_id):
        if not self.user:
            self.redirect('/login')
            
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            return self.write("no longer there to retrieve")
        return self.render("permalink.html", post = post, user=self.user)
    
    def post(self,post_id):
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = db.get(key)
        
        if not self.user.name == post.blogger_name:
            return self.write("cant delete another users post")
        
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            return self.write('blog not in database')
        db.delete(key)
        return self.redirect('/')

class DeleteComment(Handler):
    def post(self,post_id):
        key = db.Key.from_path('Comment', int(post_id), parent=comment_key())
        comment = db.get(key)
        if not comment:
            return self.write('no comment in database')
        if not self.user.name == comment.commentor:
            return self.write("cant delete another users comment")
        print "user, bloger: ", self.user.name,  comment.commentor
        comment.delete()
        return self.redirect('/blog/%s' % str(comment.post_id))
        
class MainPage(Handler):
    def default_blog(self, subject="", content=""):
        blog_db = Blog.all().order("-created").fetch(15)
        return self.render("main.html",subject=subject, content=content, blog_db= blog_db, user=self.user)
    
    def get(self):
        return self.default_blog()

    def post(self):
        if not self.user:
            return self.redirect("/login")
        return self.default_blog()

class LikePost(Handler):
    def get(self,post_id):
        if not self.user:
            return self.redirect("/login")
        return self.redirect("/")
    
    def post(self,post_id):
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            return self.write('no likes')
        if self.user:
            if not post.blogger_name == self.user.name:
                if self.user.name not in post.users_liked:
                    post.likes += 1
                    post.users_liked.append(self.user.name)
                    post.put()
                    return self.redirect("/")
                
                error = "you already liked this post!"
                return self.response.out.write(error)
            
            error = "you cant like your own post"
            return self.response.out.write(error)
        
        return self.redirect("/login")

class DisLikePost(Handler):
    
    def get(self,post_id):
        if not self.user:
            return self.redirect("/login")
        
        return self.redirect("/")
    
    def post(self,post_id):
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            return self.write('no dislikes')
        if self.user:
                if self.user.name in post.users_liked:
                    post.likes -= 1
                    post.users_liked.remove(self.user.name)
                    post.put()
                    return self.redirect("/")
                else:
                    error = "cant dislike what you didnt like!"
                    return self.response.out.write(error)
                    
        else:
            return self.redirect("/login")

class EditPost(Handler):
    def get(self, post_id):
        key= db.Key.from_path('Blog', int(post_id), parent=blog_key())
        p= db.get(key)
        
        if not self.user.name == p.blogger_name:
            error = "can't edit others posts"
            return self.response.out.write(error)
        
        if not p:
            return self.error(404)
                
    
        if not self.user:
            return self.redirect("/login")

            
        return self.render("editpost.html", subject=p.subject,content=p.content, user=self.user)
                


    def post(self,post_id):
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = db.get(key)
        
        if not self.user.name == post.blogger_name:
            print "user, bloger: ", self.user.name,  post.blogger_name
            return self.write("cant edit another users post")
        
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        p = db.get(key)

        if not p:
            return self.error(404)

        edit_subject = self.request.get('subject')
        edit_content = self.request.get('content')

        if edit_subject and edit_content:
            p.subject = edit_subject
            p.content = edit_content
            p.put()
            return self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            return self.render("editpost.html", p=p, error=error)

class EditComment(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Comment', int(post_id), parent=comment_key())
        comment = db.get(key)
        if not self.user.name == comment.commentor:
            return self.write("cant edit another users comment")
       
		
        if not comment:
            return self.error(404)
                
    
        if not self.user:
            return self.redirect("/login")
        key = db.Key.from_path('Comment', int(post_id), parent=blog_key())
        post = db.get(key)
    
        self.render("editcomment.html",content=comment.content, user=self.user)
                


    def post(self,post_id):
        key = db.Key.from_path('Comment', int(post_id), parent=comment_key())
        comment = db.get(key)
        
        if not self.user.name == comment.commentor:
            print "user, bloger: ", self.user.name,  comment.commentor
            self.redirect('/login')
        
        if not comment:
            return self.error(404)

        edit_content = self.request.get('content')
        print "content: ", edit_content 
        if edit_content:
            comment.content = edit_content
            comment.put()
        
            return self.redirect('/blog/%s' % str(comment.post_id))
        

class MyBlogs(Handler):
    def default_blog(self, subject="", content=""):
        user_id = self.user.key().id()
        
        my_blogs = Blog.all().filter('user =',  user_id)
        user = self.user.name
        self.render("myblog.html",subject=subject, content=content, blog_db= my_blogs, username= user,user=self.user)
        
       
    def get(self):
        if not self.user:
            return self.redirect("/login")
        
        return self.default_blog()
            
             
    def post(self):
        pass

app = webapp2.WSGIApplication([('/?', MainPage),
                               ('/myblog', MyBlogs),
                               ('/signup', SignUpHandler),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/newpost', NewPost),
                               ('/blog/([0-9]+)', PostPage),
                               ('/edit/([0-9]+)', EditPost),
                               ('/editcomment/([0-9]+)', EditComment),
                               ('/like/([0-9]+)', LikePost),
                               ('/dislike/([0-9]+)', DisLikePost),
                               ('/delete/([0-9]+)', DeletePost),
                               ('/deletecomment/([0-9]+)', DeleteComment),
                               ], debug=True)
