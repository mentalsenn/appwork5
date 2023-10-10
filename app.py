#Packaging for EC2 Ubuntu

from flask import Flask, request
from processSCAN import *
from wessyMetrics import *
import validators, time, logging, dash

#<iframe src="the-url-of-your-dash-app" style="border: none;"/>

logging.basicConfig(filename='wessy.log', level=logging.DEBUG)
app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def wessyform():
    try:
        if request.method == 'POST':  #this block is only entered when the form is submitted
            aname = request.form.get('appname')
            aurl  = request.form.get('appurl')
            if validators.url(aurl) and aname.isalnum():
                urscore = getText(aname, aurl)
                avgscore = getMetrics()
                time.sleep(10)
            else:
                return '''<h1>URL INPUT ERROR</h1>'''
            return '''Industry Average Score: '''+str(avgscore+100)+'''<br><br>Your Score: '''+str(urscore+100)+'''<br><br><iframe src="http://127.0.0.1:8049/" title="Dashboard"></iframe>'''

        return '''<form method="POST">
                      App Name: <input type="text" name="appname"><br><br>
                      App URL: <input type="text" name="appurl"><br><br>
                      <input type="submit" value="Submit"><br>
                </form>'''
    except ValueError:
        '''<h1>App Name was not recognizable.</h1>'''
        logging.DEBUG('Flask error')

if __name__ == '__main__':
    app.run()