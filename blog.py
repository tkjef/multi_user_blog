import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'simpsons'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

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
        self.user = uid and User.by_id(int(uid)) 

def render_article(response, article):
    response.out.write('<b>' + article.subject + '</b><br>')
    response.out.write(article.content)

def render_comment(response, comment):
    response.out.write('<b>' + comment.subject + '</b><br>')
    response.out.write(comment.content)

class MainPage(Handler):
  def get(self):
      self.write("<div style='margin: 100 auto; text-align: center;'><h2>the blizzog</h2>" +
              "<a href='/blog/'>view posts</a><br>" +
              "<a href='/blog/newpost'>new post</a></div>"
              )


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

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
	u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(Handler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog/welcome')

class Login(Handler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class Welcome(Handler):
    def get(self):
	if self.user:
	    # self.render('welcome.html', username = str(self.user.key().id()))
	    self.render('welcome.html', username = self.user.name)
	else:
	    self.redirect('/blog/signup')


##### blog stuff
class Article(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    user_id = db.IntegerProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("article.html", a = self)

class Comment(db.Model):
    article_id = db.IntegerProperty(required = True)
    content = db.TextProperty(required = True)
    user_id = db.IntegerProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", c = self)

class Blog(Handler):
    def get(self):
        # articles = db.GqlQuery("select * from Article order by created desc limit 10")
        articles = Article.all().order('-created')      
        self.render("blog.html", articles=articles)

class Commentlist(Handler):
    def get(self):
        comments = Comment.all().order('-created')
        self.render("commentlist.html", comments=comments)

class PostPage(Handler):
    def get(self, article_id):
        key = db.Key.from_path('Article', int(article_id))
        article = db.get(key)

        if not article:
            self.error(404)
            return

        self.render("individualarticle.html", article = article)

class CommentPage(Handler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        if not comment:
            self.error(404)
            return

        self.render("individualcomment.html", comment = comment)

class NewPost(Handler):
    def get(self):
	if self.user:
	    self.render("newpost.html")
	else:
	    self.redirect("/blog/login")

    def post(self):
	if not self.user:
	    self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            a = Article(subject = subject, content = content, user_id = self.user.key().id())
            a.put()
            self.redirect('/blog/%s' % str(a.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class NewComment(Handler):
    def get(self, article_id):
        key = db.Key.from_path('Article', int(article_id))
        a = db.get(key)
        if self.user:
            self.render("newcomment.html")
        else:
            self.redirect("/blog/login")

    def post(self, article_id):
        if not self.user:
            self.redirect('/blog')

        content = self.request.get('content')

        if article_id and content:
            c = Comment(article_id = int(article_id), content = content, user_id = self.user.key().id())
            c.put()
            self.redirect('/blog/comment/%s' % str(c.key().id()))
        else:
            error = "content please!"
            self.render("newcomment.html", article_id=article_id, content=content, error=error)

class EditPost(Handler):
    def get(self, article_id):
        key = db.Key.from_path('Article', int(article_id))
        a = db.get(key)

        if self.user and self.user.key().id() == a.user_id:
            self.render("editpost.html", subject=a.subject, content=a.content)
        else:
            # self.redirect('/blog/%s' % str(a.key().id()), error = error)
            error = "You don't have access to edit this post."
            self.render("article_error.html", a=a, error=error)
            # self.render("individualarticle2.html", subject=a.subject, content=a.content, error=error)
            # self.render("individualarticle2.html", a=a, error=error)
            # self.render("individualarticle.html", article = a, error = error)
            # self.write("You don't have access to edit this post.")

    def post(self, article_id):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
	    key = db.Key.from_path('Article', int(article_id))
            a = db.get(key)
            a.subject = subject
	    a.content = content
            a.put()
            self.redirect('/blog/%s' % str(a.key().id()))
        else:
            error = "subject and content, please!"
            self.render("editpost.html", subject=subject, content=content, error=error)

class EditComment(Handler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        c = db.get(key)

        if self.user and self.user.key().id() == c.user_id:
            self.render("editcomment.html", content=c.content)
        else:
            error = "You don't have access to edit this comment."
            self.render("comment_error.html", c=c, error=error)

    def post(self, comment_id):
        print comment_id

        if not self.user:
            self.redirect('/blog')

        content = self.request.get('content')

        if content:
            key = db.Key.from_path('Comment', int(comment_id))
            c = db.get(key)
            c.content = content
            c.put()
            print c.key().id()
            self.redirect('/blog/comment/%s' % str(c.key().id()))
        else:
            error = "content, please!"
            self.render("editcomment.html", content=content, error=error)

class DeletePost(Handler):
    def get(self, article_id):
        key = db.Key.from_path('Article', int(article_id))
        a = db.get(key)

        if self.user and self.user.key().id() == a.user_id:
            a_subject = a.subject
	    a.delete()
	    self.write(a_subject + " has been deleted.")
        else:
            self.write("You don't have access to delete this post.")

class DeleteComment(Handler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        c = db.get(key)

        if self.user and self.user.key().id() == c.user_id:
            c_id = str(c.key().id())
            c.delete()
            self.write(c_id + " has been deleted.")
        else:
            self.write("You don't have access to delete this post.")

class Likepost(db.Model):
    like = db.BooleanProperty(required = True)
    article_id = db.IntegerProperty(required = True)
    user_id = db.IntegerProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

class Like(Handler):
    def get(self, article_id):
        key = db.Key.from_path('Article', int(article_id))
        a = db.get(key)

        if self.user and self.user.key().id() != a.user_id:
	    lp = Likepost.all().filter('user_id =', self.user.key().id())
            lp.filter('article_id =', a.key().id())
            lpg = lp.get()
            if lpg:
	    	self.write("Already liked.")
	    else:
	    	lp = Likepost(like = True, article_id = a.key().id(), user_id = self.user.key().id())
            	lp.put()
                self.write("You have liked %s" % a.subject)
        elif not self.user:
            error = "You have to be logged in to like posts."
            self.render("article_error.html", a=a, error=error)
	else:
	    error =  "You can't like your own posts."
            self.render("article_error.html", a=a, error=error)

class Unlike(Handler):
    def get(self, article_id):
	key = db.Key.from_path('Article', int(article_id))
	a = db.get(key)

	if self.user and self.user.key().id() != a.user_id:
            lp = Likepost.all().filter('user_id =', self.user.key().id())
            lp.filter('article_id =', a.key().id())
            lpg = lp.get()
            if lpg:
                lpg.delete()
                self.write("You have unliked %s" % a.subject)
        elif not self.user:
            error = "You have to be logged in to unlike posts."
            self.render("article_error.html", a=a, error=error)
        else:
            error =  "You can't unlike your own posts."
            self.render("article_error.html", a=a, error=error)

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', Blog),
                               ('/blog/newpost', NewPost),
                               ('/blog/([\d]+)/newcomment', NewComment),
                               ('/blog/([\d]+)', PostPage),
                               ('/blog/comment/([\d]+)', CommentPage),
                               ('/blog/([\d]+)/edit', EditPost),
                               ('/blog/comment/edit/([\d]+)', EditComment),
                               ('/blog/([\d]+)/delete', DeletePost),
                               ('/blog/comment/([\d]+)/delete', DeleteComment),
                               ('/blog/([\d]+)/like', Like),
                               ('/blog/([\d]+)/unlike', Unlike),
			       ('/blog/signup', Register),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout),
                               ('/blog/welcome', Welcome),
                               ],
                              debug=True)
