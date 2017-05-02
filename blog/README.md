# Udacity Blog Project
As part of [Udacity's Full-Stack Web Developer program](https://www.udacity.com/course/full-stack-web-developer-nanodegree--nd004), create a webpage, powered by Python, featuring Multi User Blog called Blog Central 

##Instructions: How to Launch Webpage
Setup

1.Install Python if necessary.

2.Install Google App Engine SDK.https://cloud.google.com/appengine/docs/standard/python/download

3.Sign Up for a Google App Engine Account.

4.Create a new project in Google’s Developer Console using a unique name.

5.Follow the App Engine Quickstart to get a sample app up and running.

6.Deploy your project with gcloud app deploy.

7.View your project at unique-name.appspot.com.

8.Web page will load.

9.When developing locally, you can use dev_appserver.py to run a copy of your app on your own computer, and access it at 'http://localhost:8080/'.


#Python
In my  `Blog`. 


##Site Usability:
     
     1. User is directed to login, logout, and signup pages as appropriate. E.g.,
        login page should have a link to signup page and vice-versa; logout page is
        only available to logged in user.

     2. Links to edit blog pages are available to users. Users editing a
        page can click on a link to cancel the edit and go back to viewing that page.

     3.Blog pages render properly. Templates are used to unify the site.
     
     4. users have MyBlog page to see only there blogs. will be able to edit and delete also.

##Accounts and Security:
    
    1.Users are able to create accounts, login, and logout correctly.
    
    2.Existing users can revisit the site and log back in without having to
    recreate their accounts each time.
    
    3.Usernames are unique. Attempting to create a duplicate user results
    in an error message.
   
    4.Stored passwords are hashed. Passwords are appropriately checked during
    login. User cookie is set securely.

##Permissions:
   
    1.Logged out users are redirected to the login page when attempting
    to create, edit, delete, or like a blog post.
    
    2.Logged in users can create, edit, or delete blog posts they
    themselves have created.
    Users should only be able to like posts once and should not be
    able to like their own post.
    
    3. Only signed in users can post comments.Users can only edit
    and delete comments they themselves have made.
    
