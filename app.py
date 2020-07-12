import os

from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
import time
import datetime as dt
import secrets
import random

## TODO check in requirements
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
## TODO cs50.sql -> lib
from cs50 import SQL
import json
import bcrypt
import jinja2
import dateutil.parser
import requests



## BEGIN SETUP

## Repalce this with the base URL of your instance
baseurl = "164.90.148.248:5000"

app = Flask(__name__)

app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

## Replace this with your database
db = SQL("sqlite:///calli.db")

## Gives Jinja the datetime module
app.add_template_filter(dt.datetime)



## BEGIN FLASK

## Landing page ##

@app.route("/")
def root():
    return render_template("homenew.html")

## Docs ##

@app.route("/docs")
def docs():
    return render_template("docs.html")

@app.route("/docs/cli")
def docs_cli():
    return render_template("docs_cli.html")

@app.route("/docs/api")
def docs_api():
    return render_template("docs_api.html")

@app.route("/docs/server")
def docs_server():
    return render_template("docs_server.html")

## WEBAPP ##

## TODO accept redirects from /register

@app.route("/dash", methods=["GET"])
def web_dash():
    if request.method == "GET":
        ## If user logged in ##
        try:
            session['user_id']
        except KeyError:
            return redirect('/login')
        else:
            ## Today ##
            now = dt.datetime.utcnow().strftime('%s')
            today_start = dt.datetime.now().strftime('%s')
            today_end = (dt.datetime.combine((dt.datetime.today()+dt.timedelta(days=1)), dt.time(0))+dt.timedelta(hours=(-1*int(session['offset'])))).strftime("%s")
            today_calendar = db.execute("SELECT * FROM calendar WHERE userid=(:userid) AND start BETWEEN (:start) AND (:end) ORDER BY start", userid=session['user_id'], start=today_start, end=str(int(today_end)-1))
            for event in today_calendar:
                event['start'] = (((dt.datetime.utcfromtimestamp(int(event['start'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
                event['end'] = (((dt.datetime.utcfromtimestamp(int(event['end'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
            ## Tomorrow ##
            tomorrow_start = (dt.datetime.combine((dt.datetime.today()+dt.timedelta(days=1)), dt.time(0))+dt.timedelta(hours=(-1*int(session['offset'])))).strftime("%s")
            tomorrow_end = (dt.datetime.combine((dt.datetime.today()+dt.timedelta(days=2)), dt.time(0))+dt.timedelta(hours=(-1*int(session['offset'])))).strftime("%s")
            tomorrow_calendar = db.execute("SELECT * FROM calendar WHERE userid=(:userid) AND start BETWEEN (:start) AND (:end) ORDER BY start", userid=session['user_id'], start=tomorrow_start, end=str(int(tomorrow_end)-1))
            for event in tomorrow_calendar:
                event['start'] = (((dt.datetime.utcfromtimestamp(int(event['start'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
                event['end'] = (((dt.datetime.utcfromtimestamp(int(event['end'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
            ## Rest of the week ##
            rest_start = (dt.datetime.combine((dt.datetime.today()+dt.timedelta(days=2)), dt.time(0))+dt.timedelta(hours=(-1*int(session['offset'])))).strftime("%s")
            reset_end = (dt.datetime.combine((dt.datetime.today()+dt.timedelta(days=7)), dt.time(0))+dt.timedelta(hours=(-1*int(session['offset'])))).strftime("%s")
            rest_calendar = db.execute("SELECT * FROM calendar WHERE userid=(:userid) AND start BETWEEN (:start) AND (:end) ORDER BY start", userid=session['user_id'], start=rest_start, end=str(int(reset_end)-1))
            ## Timezone deltas ##
            for event in rest_calendar:
                event['day'] = (((dt.datetime.utcfromtimestamp(int(event['start'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%a %d %b %y"))
                event['start'] = (((dt.datetime.utcfromtimestamp(int(event['start'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
                event['end'] = (((dt.datetime.utcfromtimestamp(int(event['end'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
            return render_template("dash.html", userid=session['user_id'], username=session['username'], today_calendar=today_calendar, tomorrow_calendar=tomorrow_calendar, rest_calendar=rest_calendar, offset=session['offset'], token=session['token'], url=baseurl)
    ## TODO ##
    else:
        return "only get"

## TODO create
@app.route("/dash/create", methods=["GET", "POST"])
def dash_create():
    if request.method == "GET":
        try:
            session['user_id']
        except KeyError:
            return redirect('/login')
        else:
            today_default = dt.datetime.now().date().strftime("%a %d %b %y")
            time_default = dt.time(12).strftime("%I:%M %P")
            duration_default = str(60)
            return render_template("dash_create.html", today_default=today_default, time_default=time_default, duration_default=duration_default, userid=session['user_id'], username=session['username'], offset=session['offset'], token=session['token'])
    elif request.method == "POST":
        print(request.form.get('name'))
        print(request.form.get('day'))
        print(request.form.get('start'))
        print(request.form.get('duration'))
        print(request.form.get('info'))

        ## Start parsing the new event
        event = {}
        event['info'] = request.form.get('info')
        event['name'] = request.form.get('name')
        if request.form.get('day'):
            try:
                date = dateutil.parser.parse(request.form.get('day'), dayfirst=True)
            except ValueError:
                render_template("dash_create.html", show_error="please enter a valid date for the event", userid=session['user_id'], username=session['username'], offset=session['offset'], token=session['token'])
        else:
            date = dt.datetime.now()

        if request.form.get('start'):
            try:
                time = dateutil.parser.parse(request.form.get('start'), dayfirst=True)
            except ValueError:
                render_template("dash_create.html", show_error="please enter a valid time for the event", userid=session['user_id'], username=session['username'], offset=session['offset'], token=session['token'])
        else:
            time = dt.datetime.combine(dt.datetime.now().date(), dt.time(12))

        if request.form.get('duration'):
            try:
                duration = int(request.form.get('duration'))
            except ValueError:
                return render_template("dash_create.html", show_error="please enter an integer duration for the event, or select reminder", userid=session['user_id'], username=session['username'], offset=session['offset'], token=session['token'])
        else:
            duration = 60

        start = ((dt.datetime.combine(date.date(), time.time()).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset'])))
        event['start'] = start.strftime("%s")

        if request.form.get('type') == "E":
            end = (start + dt.timedelta(minutes=duration))
            event['end'] = end.strftime("%s")
        else:
            event['end'] = str(0)

        if request.form.get('type') == "event":
            event['type'] == "E"
        elif request.form.get('type') == 'reminder':
            event['type'] == "R"
        else:
            event['type'] == "?"

        url = baseurl + "/events"
        
        r = lambda: random.randint(0,255)
        existing = db.execute("SELECT eventhex FROM calendar WHERE userid=(:userid)", userid=session['user_id'])
        eventhex = '@%02X%02X%02X' % (r(),r(),r())
        ## Check for eventhex collission ##
        while any(d['eventhex'] == eventhex for d in existing):
            eventhex = '@%02X%02X%02X' % (r(),r(),r())

        ## Create event ##
        pending = db.execute("INSERT INTO calendar (userid, eventhex, type, name, start, end, info) VALUES (:userid, :eventhex, :etype, :name, :start, :end, :info)", userid=session['user_id'], eventhex=eventhex, etype=event['type'], name=event['name'], start=event['start'], end=event['end'], info=event['info'])
        
        if pending == None:
            return render_template("dash_create.html", show_error="event creation failed. please try again.", userid=session['user_id'], username=session['username'], offset=session['offset'], token=session['token'])
        else:
            return redirect("/dash")


@app.route("/dash/edit", methods=["GET", "POST"])
def dash_edit():
    ## If logged in
    if request.method == "GET":
        try:
            session['user_id']
        except KeyError:
            return redirect('/login')
        else:
            ## query event arg
            eventhex = '@' + request.args.get('event').upper()
            event = db.execute("SELECT * FROM calendar WHERE eventhex=:eventhex AND userid=:userid", eventhex=eventhex, userid=session['user_id'])[0]
            ## Convert to dt object and add user timezone offset
            event['day'] = (((dt.datetime.utcfromtimestamp(int(event['start'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%a %d %b %y"))
            event['duration'] = (int(event['end']) - int(event['start']))/60
            event['start'] = (((dt.datetime.utcfromtimestamp(int(event['start'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
            return render_template("dash_edit.html", event=event, userid=session['user_id'], username=session['username'], offset=session['offset'], token=session['token'], eventhex=request.args.get('event').lower())
    elif request.method == "POST":
        ## get old event for error redirect
        ## TODO some new info isnt sent
        eventhex = '@' + request.args.get('event').upper()
        event = db.execute("SELECT * FROM calendar WHERE eventhex=:eventhex AND userid=:userid", eventhex=eventhex, userid=session['user_id'])[0]
        old_start = ((dt.datetime.utcfromtimestamp(int(event['start'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset'])))
        old_end = ((dt.datetime.utcfromtimestamp(int(event['end'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset'])))
        event['day'] = old_start.strftime("%a %d %b %y")
        event['duration'] = (int(event['end']) - int(event['start']))/60
        event['start'] = old_start.strftime("%I:%M%p")

        ## Start parsing new fields
        if request.form.get("info"):
            new_info = request.form.get('info')
        else:
            new_info = event['info']

        ## Duration
        if request.form.get("duration"):
            if event['type'] == "E":
                try:
                    new_duration = int(request.form.get('duration'))
                except ValueError:
                    return render_template("dash_edit.html", show_error="please enter an integer number of minutes for event duration", event=event, userid=session['user_id'], username=session['username'], offset=session['offset'], token=session['token'], eventhex=request.args.get('event').lower())
        else:
            ## default to old offset
            new_duration = int(event['duration'])
        ## Date
        if request.form.get("day"):
            try:
                new_date = dateutil.parser.parse(request.form.get('day'), dayfirst=True)
            except ValueError:
                return render_template("dash_edit.html", show_error="please enter a valid date", event=event, userid=session['user_id'], username=session['username'], offset=session['offset'], token=session['token'], eventhex=request.args.get('event').lower())
        else:
            new_date = old_start
        ## Start
        if request.form.get("start"):
            try:
                new_time = dateutil.parser.parse(request.form.get('start'), dayfirst=True)
            except ValueError:
                return render_template("dash_edit.html", show_error="please enter a valid start time", event=event, userid=session['user_id'], username=session['username'], offset=session['offset'], token=session['token'], eventhex=request.args.get('event').lower())
        else:
            new_time = old_start
        ## Combine new date and time to start ##
        new_start = (dt.datetime.combine(new_date.date(), new_time.time())+dt.timedelta(hours=(-1*int(session['offset']))))
        ## If event, calculate end 33
        if event['type'] == "E":
            new_end = (new_start + dt.timedelta(minutes=int(new_duration))).strftime('%s')
        else:
            ## Else its a remind ##
            new_end = str(0)
        updated_event = db.execute("UPDATE calendar SET start=:start, end=:end, info=:info WHERE eventhex=(:eventhex) AND userid=(:userid)", userid=session['user_id'], eventhex=eventhex, start=new_start.strftime('%s'), end=new_end, info=new_info)
        ## If DB updated one event ##
        if updated_event == 1:
            return redirect('/dash')
        else:
            return render_template("dash_edit.html", show_error="edit unsuccessful. please try again", event=event, userid=session['user_id'], username=session['username'], offset=session['offset'], token=session['token'], eventhex=request.args.get('event').lower())



@app.route("/dash/events")
def dash_events():
    if request.method == "GET":
        ## If user logged in ##
        try:
            session['user_id']
        except KeyError:
            return redirect('/login')
        else:
            ## get events until the end of time ##
            today_start = dt.datetime.now().strftime('%s')
            events_calendar = db.execute("SELECT * FROM calendar WHERE userid=(:userid) AND type='E' AND start>=(:start) ORDER BY start", userid=session['user_id'], start=today_start)
            for event in events_calendar:
                event['day'] = (((dt.datetime.utcfromtimestamp(int(event['start'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%a %d %b %y"))
                event['start'] = (((dt.datetime.utcfromtimestamp(int(event['start'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
                event['end'] = (((dt.datetime.utcfromtimestamp(int(event['end'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
            return render_template("dash_events.html", userid=session['user_id'], username=session['username'], events_calendar=events_calendar, offset=session['offset'])
    ## TODO
    else:
        return "no"


@app.route("/dash/reminders")
def dash_remind():
    if request.method == "GET":
        try:
            session['user_id']
        except KeyError:
            return redirect('/login')
        else:
            ## get reminds from now to the end of time ##
            today_start = dt.datetime.now().strftime('%s')
            reminds_calendar = db.execute("SELECT * FROM calendar WHERE userid=(:userid) AND type='R' AND start>=(:start) ORDER BY start", userid=session['user_id'], start=today_start)
            for event in reminds_calendar:
                event['day'] = (((dt.datetime.utcfromtimestamp(int(event['start'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%a %d %b %y"))
                event['start'] = (((dt.datetime.utcfromtimestamp(int(event['start'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
                event['end'] = (((dt.datetime.utcfromtimestamp(int(event['end'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
            return render_template("dash_reminds.html", userid=session['user_id'], username=session['username'], reminds_calendar=reminds_calendar, offset=session['offset'])
    ## TODO
    else:
        return "no"

@app.route("/logout")
def logout():
    """Log user out"""
    # Forget any user_id
    session.clear()
    # Redirect user to login form
    return redirect("/")

@app.route("/login", methods=["GET", "POST"])
def web_login():
    if request.method == "GET":
        return render_template("login.html")
    elif request.method == "POST":
        ## Clear session
        session.clear()
        session['offset'] = request.form.get('timeoffset')
        ## If username andor password arent supplied
        if not request.form.get("username"):
            return render_template("login.html", show_error="please provide a username")
        elif not request.form.get("password"):
            return render_template("login.html", show_error="please provide a password")
        ## Get the user
        users = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))
        ## If the username exists
        if users:
            ## If the hash is right
            if bcrypt.checkpw(request.form.get("password").encode('utf-8'), users[0]['hash']):
                session["user_id"] = users[0]["userid"]
                session["token"] = users[0]["token"]
                session["username"] = users[0]["username"]
                return redirect('/dash')
            else:
                return render_template("login.html", show_error="invalid username or password")
        else:
                return render_template("login.html", show_error="invalid username or password")
    else:
        return jsonify("method not allowed"), 405, {'ContentType':'application/json'}

@app.route("/register", methods=["GET", "POST"])
def web_register():
    if request.method == "GET":
        return render_template("register.html")
    elif request.method == "POST":
        ## Clientside checks should prevent empty form submission
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if password != confirmation:
            return render_template("register.html", show_error="passwords must match")
        if not username or not password:
             return render_template("register.html", show_error="enter a username and a password")
        else:
            ## This is not guaranteed to be unique - just extremely unlikely (one in ~2^2600 before a collision)
            token = secrets.token_urlsafe(42)
            db.execute("INSERT INTO users (username, hash, token) VALUES (:username, :hash, :token)", username=username, hash=bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(5)), token=token)
            ## TODO redirect to dashboard
            return redirect("/")
    else:
        return jsonify("method not allowed"), 405, {'ContentType':'application/json'}


## API ##

@app.route("/api/events", methods=["POST", "GET", "DELETE", "PATCH"])
def new_event():
    auth = db.execute("SELECT * FROM users WHERE token=(:token)", token=request.headers['token'])
    if auth:
        ## TODO move auth to before request.method
        if request.method == "GET":
            ## If GET by start and end time
            if request.args.get('start') and request.args.get('end'):
                start = request.args.get('start')
                end = request.args.get('end')
                today_calendar = db.execute("SELECT * FROM calendar WHERE userid=(:userid) AND start BETWEEN (:start) AND (:end) ORDER BY start", userid=auth[0]['userid'], start=start, end=end)
                return jsonify(today_calendar)
            ## If GET by event id
            elif request.args.get('eventhex'):
                print(request.args.get('eventhex'))
                today_calendar = db.execute("SELECT * FROM calendar WHERE userid=(:userid) AND eventhex=(:eventhex)", userid=auth[0]['userid'], eventhex="@"+request.args.get('eventhex').upper())
                return jsonify(today_calendar)
            ## TODO If GET by start time onwards
            elif request.args.get('start'):
                start = request.args.get('start')
                today_calendar = db.execute("SELECT * FROM calendar WHERE userid=(:userid) AND start>=(:start) ORDER BY start", userid=auth[0]['userid'], start=start)
                return jsonify(today_calendar)
            ## else...
        elif request.method == "POST":
            ## Load content ##
            content = request.json
            ## Random hex lambda ##
            r = lambda: random.randint(0,255)
            existing = db.execute("SELECT eventhex FROM calendar WHERE userid=(:userid)", userid=auth[0]['userid'])
            eventhex = '@%02X%02X%02X' % (r(),r(),r())
            ## Check for eventhex collission ##
            while any(d['eventhex'] == eventhex for d in existing):
                eventhex = '@%02X%02X%02X' % (r(),r(),r())
            ## If there is no end time ##
            try:
                content['end']
            ## End defaults to 0 (reminds) ##
            except KeyError:
                content['end'] = str(0)
            ## Create event ##
            db.execute("INSERT INTO calendar (userid, eventhex, type, name, start, end, info) VALUES (:userid, :eventhex, :etype, :name, :start, :end, :info)", userid=auth[0]['userid'], eventhex=eventhex, etype=content['type'], name=content['name'], start=content['start'], end=content['end'], info=content['info'])
            ## Return the chosen eventhex ##
            return json.dumps({'eventhex':eventhex}), 200, {'ContentType':'application/json'}
        elif request.method == "DELETE":
            content = request.json
            ## Set a counter for number of events deleted ##
            deleted = 0
            ## Start deleting ##
            for eventhex in content['hex']:
                deleted += db.execute("DELETE FROM calendar WHERE userid=(:userid) AND eventhex=(:eventhex)", userid=auth[0]['userid'], eventhex=eventhex.upper())
            ## If all the events got deleted ##
            if deleted == len(content['hex']):
                ## Return the successfully deleted events ##
                return json.dumps({'eventhex':eventhex}), 204, {'ContentType':'application/json'}
            else:
                ## Else you fucked up ##
                return jsonify("failed"), 401, {'ContentType':'application/json'}
        elif request.method == "PATCH":
            ## re-create the eventhex string
            eventid = "@" + request.args.get('eventhex')
            content = request.json
            ## Timestamp generation is all clientside
            updated_event = db.execute("UPDATE calendar SET start=:start, end=:end, info=:info WHERE eventhex=(:eventid) AND userid=(:userid)", userid=auth[0]['userid'], eventid=eventid.upper(), start=content['start'], end=content['end'], info=content['info'])
            if updated_event == 1:
                return jsonify("success"), 204, {'ContentType':'application/json'}
            else:
                return jsonify("failed"), 404, {'ContentType':'application/json'}
        else:
            return jsonify("method not allowed"), 405, {'ContentType':'application/json'}
    else:
        return jsonify("unauthorized"), 401, {'ContentType':'application/json'}


@app.route("/api/login", methods=["POST"])
def login():
    ## Same as /login
    if request.method == "POST":
        content = request.json
        users = db.execute("SELECT * FROM users WHERE username=(:username)", username=content['username'])
        if users:
            if bcrypt.checkpw(content['password'].encode('utf-8'), users[0]['hash']):
                return jsonify(users[0]['token']), 200, {'ContentType':'application/json'}
            else:
                return jsonify("unauthorized"), 401, {'ContentType':'application/json'}
    else:
        return jsonify("method not allowed"), 405, {'ContentType':'application/json'}
